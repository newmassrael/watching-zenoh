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
# R2366 -- `runtime-tokio` CLOSED, so it leaves the PARTIAL population entirely
# and takes its own row with it. It sat in REACHED (67 -> 66) and its reason
# carried exactly one AMBIGUOUS citation and one upstream one (81 -> 80), which
# was ATTRIBUTED rather than netted: running `citation_audit` over that atom's
# OLD reason alone answers (0 wz, 1 ambiguous, 1 upstream), so the wz-citation
# pin correctly does not move and the other two move by exactly that row.
# R2368 -- `declare-final` CLOSED, so it leaves the PARTIAL population and takes
# its row with it, exactly as `runtime-tokio` did above. ATTRIBUTED, not netted:
# `atom_test_graph.graph()` gives it 0 owned symbols, so it sat in NO-SYMBOL
# (3 -> 2) and never in REACHED or UNREACHED, which is why those two do not move.
# Running `citation_audit` over its OLD reason ALONE answers (9 wz, 0 ambiguous,
# 13 upstream): the wz pin therefore falls by exactly 9 (373 -> 364) and the
# AMBIGUOUS pin correctly does not move at all. Its NEW reason's own 3 wz
# citations are not counted here because this census reads PARTIAL reasons only.
# R2369 -- `liveliness-subscriber` CLOSED, same shape again and ATTRIBUTED the
# same way. `atom_test_graph.graph()` gives it 29 owned symbols with 24
# referenced, so it sat in REACHED (66 -> 65) and neither NO-SYMBOL nor
# UNREACHED moves. `citation_audit` over its OLD reason ALONE answers (9 wz, 0
# ambiguous, 15 upstream), so the wz pin falls by exactly 9 (364 -> 355) and the
# AMBIGUOUS pin again does not move at all.
# R2371 -- `transport-stats` CLOSED, the same shape a third time and ATTRIBUTED
# the same way rather than netted. It owns symbols that tests reference, so it
# sat in REACHED (65 -> 64) and neither UNREACHED nor NO-SYMBOL moves. Running
# `citation_audit` over its OLD reason ALONE answers (3 wz, 1 ambiguous, 2
# upstream), so the wz pin falls by exactly 3 (355 -> 352) and -- unlike the two
# closes above -- the AMBIGUOUS pin DOES move, by exactly 1 (80 -> 79). Its NEW
# reason's citations are not counted here: this census reads PARTIAL reasons
# only, and that atom is no longer one.
# R2374 -- every pin here STAYS, and the round it stayed through is worth a note
# because the number moved twice on the way. `adminspace-read` and
# `adminspace-write` both gained a CORRECTION and both stay PARTIAL, so
# REACHED / UNREACHED / NO-SYMBOL cannot move; the wz count went 352 -> 354 on the
# first draft of those corrections and came back to 352 when their upstream
# citations were removed. They were removed because `upstream_citation_anchor_gate`
# refused them: the adminspace runtime module was named WITHOUT its root, both
# root-less ratchets are exactly on budget, and that gate's instruction is to
# repair the citation rather than raise the budget. The facts those sentences
# rest on are cited, with their roots, earlier in each reason.
# ⚠ R2385 -- the sentence above HAD WRITTEN THAT PATH OUT while explaining its
# removal, so it re-entered the very residue it was describing. Fourth sighting
# of the class (R2241, R2318, R2371, here), and the first in THIS file. Described
# now, never written. It is one of the occurrences debt 667 enumerates.
# R2385 -- `declare-keyexpr` CLOSED, and the pins move for TWO reasons at once,
# which is why both are written down instead of one number being adjusted.
#
# THIS ROUND'S OWN DELTA, attributed the way every entry above attributes its
# own: the atom sat in REACHED (it owns 57 symbols, all 57 referenced by tests),
# so REACHED falls by exactly 1 and neither UNREACHED nor NO-SYMBOL moves.
# `citation_audit` over its OLD reason ALONE answers (7 wz, 1 ambiguous, 9
# upstream), so the wz pin falls by exactly 7 and the AMBIGUOUS pin by exactly 1.
#
# ⚠ THE INHERITED DRIFT, which this round ADOPTS rather than hides. These pins
# were last correct at R2374. SEVEN atoms closed after it without following them
# down -- `session-reconnect` (R2376), the four `transport-link-*` (R2380), and
# `declare-token` / `declare-subscriber` (R2383) -- so REACHED had already fallen
# 64 -> 57 before this round touched anything, and the wz / ambiguous pins
# 352 -> 312 and 79 -> 75. The arithmetic is checkable: 64 - 7 = 57, which is what
# the census printed at this commit's parent. The gate has therefore been RED on
# the hosted run for four rounds, seen by nobody, which is the cost of a pin that
# only the lane can check. The numbers below are the MEASURED values after this
# round's mutation; the seven-atom part of the fall is bookkeeping, not a
# measurement this round made.
# R2394 -- `access-downsampling` RE-GRADED against the pin (open-debt item 675),
# and as at R2385 the pins move for two reasons at once, so both are written.
#
# THIS ROUND'S OWN DELTA, measured with this file's own `citation_audit` over the
# atom's OLD and NEW reason alone: 3 wz / 2 ambiguous before, 6 wz / 1 ambiguous
# after, so the wz pin rises by exactly 3 and the AMBIGUOUS pin FALLS by exactly
# 1. REACHED does not move at all -- the atom is COMPLETE and was already outside
# the PARTIAL population this axis counts, which is also why renaming its
# `message_kind` to `message_kinds` moves nothing here: a store-wide read shows
# that symbol cited by this atom and no other.
#
# THE INHERITED DRIFT, adopted rather than hidden, exactly as the R2385 entry
# above had to adopt its own. These pins were last correct at R2385. Since then
# R2390 closed `transport-multicast`, which was a REACHED member, so REACHED had
# already fallen 56 -> 55 before this round touched anything; and R2386-R2393
# rewrote reasons without following the citation pins, which had already carried
# wz 305 -> 311 and ambiguous 74 -> 76. The arithmetic is checkable against this
# commit's parent and this round's own delta: 311 + 3 = 314 and 76 - 1 = 75,
# which is what the census prints here. The gate has therefore been RED on the
# hosted run since R2390 with nobody reading it -- the same cost the R2385 entry
# recorded, for the same reason, four rounds later.
#
# Round 2412 -- `locator-iface` re-declared at the pin (open-debt item 675).
#
# THIS ROUND'S OWN DELTA ON EVERY AXIS HERE IS ZERO, and that is derived, not
# assumed: `locator-iface` is graded COMPLETE, and `partial_atoms()` admits only
# PARTIAL reasons, so a rewrite of that atom's whole reason -- fourteen new
# anchored citations included -- cannot reach any count on this page. The census
# printed 315 both before and after the mutation, which is the check.
#
# THE INHERITED DRIFT, adopted rather than hidden. The wz pin has been ONE low
# since `5c6446bc` (ledger `Round 2405`, `access-extauth-usrpwd` verified in
# full), which took that atom from 4 wz citations to 5 without moving the pin.
# That is the whole of the +1: replaying every store-touching commit since the
# pin was last set through this file's own `citation_audit` moves the count at
# exactly one commit and no other. Six rounds ran red on the hosted lane behind
# it, which is the cost this gate's own message names and the reason it is
# adopted HERE rather than filed for later -- the attribution is in hand now.
#
# Adopting a neighbour's drift is what the R2394 block above did for R2386-R2393
# and the R2385 block before it. The rule the three share: the pin moves with a
# NAMED mover, so the next reader can tell an unpaid measurement from an unread
# one.
#
# Round 2417 -- `transport-multicast` re-declared at the pin (open-debt item
# 675), and this round's OWN delta on every axis here is ZERO, derived the same
# way `Round 2412` derived its own: that atom is graded COMPLETE, and
# `partial_atoms()` admits only PARTIAL reasons, so rewriting its whole reason
# -- nine new anchored upstream citations included -- cannot reach any count on
# this page. The census printed wz 301 / ambiguous 73 both before and after the
# mutation, which is the check.
#
# THE INHERITED DRIFT, ADOPTED WITH BOTH MOVERS NAMED, because the attribution
# is in hand rather than guessed. Replaying every store-touching commit since
# the pin was last set through this file's own `citation_audit` moves the count
# at exactly TWO commits and no other:
#
#   * the commit that re-declared `adminspace-metrics` (ledger `Round 2414`)
#     -- wz -8, ambiguous -2;
#   * the commit that re-declared `adminspace-core`   (ledger `Round 2415`)
#     -- wz -6, ambiguous unchanged.
#
# The arithmetic is checkable and exact: 315 - 8 - 6 = 301 and 75 - 2 = 73,
# which is what the census prints here. Both were item-675 re-gradings that
# moved the RATCHET budget in their own commit and left these pins behind --
# the same shape the two blocks above record, and for the same structural
# reason: `grading_pin_ratchet.py` runs in the pre-push hook while this census
# runs only in Layer C0, so a round that pays one instrument cannot see the
# other object. Layer C0 has therefore been RED for the four rounds behind
# those two commits, dying HERE before the citation gates that sit after it --
# which is why a later reader must not read a green anchor gate as evidence
# that this page was reached.
# Round 2422 -- `session-extqos` re-declared at the pin (open-debt item 675),
# and this time the mover IS this round, not a neighbour. That atom is graded
# PARTIAL, so unlike R2417's COMPLETE it sits inside `partial_atoms()` and its
# rewritten reason reaches this page directly: wz 301 -> 302, one new citation of
# `crates/wz-session-core/src/extqos.rs`, which the re-measurement names because
# the false protocol-absence sentences it corrected are in that file. Every other
# axis is UNCHANGED and that was read rather than assumed -- reached 55,
# unreached 3, no-symbol 2, ambiguous 73 all identical before and after the
# mutation, so the single-count move is the whole of this round's delta and no
# neighbour's drift is being adopted here.
# Round 2436 -- `storage-mgr-dynamic-volume-loading` re-declared at the pin
# (open-debt item 675), and as in Round 2422 the mover IS this round. The atom is
# graded PARTIAL, so its rewritten reason reaches this page directly: wz 302 ->
# 306, FOUR new citations, and they are four because the re-measurement is a
# PRODUCT change and each names a site it built or measured --
# `crates/wz-ap-demo/src/args.rs` twice (the name-keyed binding and its test
# module), `crates/wz-ap-demo/src/runner.rs` once (the duplicate-id refusal at the
# load site), and `crates/wz-session-core/src/storage_config.rs` once, which is
# the SEAM the atom stays PARTIAL on.
#
# AMBIGUOUS WAS MOVED AND THEN MOVED BACK, which is worth recording because the
# first reason draft raised it 73 -> 74. The cause was a bare `lib.rs:124,220` in
# the prose -- the upstream line-pair the grading citation used to name -- and a
# bare filename matches many tracked files, so it landed as ambiguous rather than
# as the upstream claim it was. Rewriting it as "lines 124 and 220 of the
# storage-manager plugin's entry module" returned the count to 73. The rule this
# instance adds to R2420's: a bare filename does not merely miss a bucket, it can
# be CLAIMED by the wrong one. Describe the path; do not type a naked basename.
# Every other axis is UNCHANGED and that was read rather than assumed -- reached
# 55, unreached 3, no-symbol 2, ambiguous 73 identical before and after.
# Round 2437 -- `session-unicast-open` re-declared at the pin (open-debt item
# 675), the mover again being this round. wz 306 -> 311, FIVE new citations, one
# per site the round built: the unknown-mandatory-extension rule and its test
# module in `crates/wz-session-core/src/ext_chain.rs`, the error variant in
# `parse_error.rs`, the call site in `inbound.rs`, and the derived recognised-id
# table in `ext_header.rs`.
#
# AMBIGUOUS HELD AT 73, and that is the R2436 lesson applied rather than
# re-learned: that round raised it to 74 by typing a bare basename into store
# prose, where it was CLAIMED as a wz citation though it was an upstream claim.
# This round's reason names upstream paths from their repository root and
# describes rather than abbreviates, so nothing landed in the wrong bucket.
# Every other axis UNCHANGED and read rather than assumed -- reached 55,
# unreached 3, no-symbol 2.
# Round 2438 -- `routing-peer` re-declared at the pin (open-debt item 675).
# wz 311 -> 314, THREE new citations, and each names a site the round used as
# evidence rather than decoration: `accept_loop.rs` @ `fn peer_loop` (the two
# false sentences this round deleted), `lib.rs` @ `pub mod linkstate_forward`
# (what refutes them), and the peer/zenohd interop test (R2236's two-leg proof
# that the deprecated key is inert, which is why this round claims no repair
# there).
#
# AMBIGUOUS HELD AT 73 for the third round running, and this time it took work:
# the first draft of the reason carried SIX unanchored upstream paths and the
# store citation gate refused it -- bare 6 -> 8, unresolved 8 -> 9. Two of them
# were bare BASENAMES (`gateway.rs`, `gossip.rs`), which is the R2436 trap, and
# one was a 1.5.0 path that cannot resolve at the pin BY CONSTRUCTION because
# the directory it names was merged away. All six were rewritten as prose
# descriptions, keeping only anchored `path` @ `needle` forms. A dead path is
# described, never cited.
# Round 2439 -- `routing-token-tables` re-declared at the pin (open-debt 675).
# wz 314 -> 315, ONE new citation: `router_forward.rs` @ `fn gateways_of`, the
# module header this round deleted a false clause from. Only one because the
# round's other work was RETIREMENT -- two residuals dropped for naming a
# capability upstream deleted -- and retiring a claim adds no wz site.
#
# AMBIGUOUS HELD AT 73 for the fourth round running.
#
# Round 2499 (open-debt item 710) -- wz 315 -> 346, THIRTY-ONE citations across
# FIFTEEN rounds, reconstructed in bulk. This is the one entry in this block
# that was not written by the round that moved the number, and the reason is
# the point: THIS AXIS WAS BLIND FOR THE WHOLE STRETCH. The leg that checks it
# sits at position 91 of `layer_c0_test_discipline`, and R2448 left that lane
# failing at leg 68 -- `wz-session-core` / `codec-fragment` declared to gate no
# public path while the scan found one -- so hosted C0 never reached this
# check again. R2498 repaired leg 68; the lane then advanced to 91 and this
# red is what it found. Every round below did the work it was FOR (the item
# 675 re-declaration ratchet, which re-anchors an atom's reason to wz sites);
# none of them was told it owed this block an entry, because nothing could
# tell them.
#
#   Round 2469  adminspace-plugins-handlers       +1
#   Round 2470  attachment-bytes                  +1
#   Round 2471  attachment-bytes                  +3
#   Round 2472  api-compat-pico                   +3
#   Round 2475  attachment-bytes                  +1
#   Round 2478  liveliness-get                    +3
#   Round 2479  adminspace-router-linkstate       +1
#   Round 2480  session-unicast-accept            +1
#   Round 2483  routing-routes                    +1
#   Round 2484  ext-pubsub-sample-miss-detection  +3
#   Round 2485  ext-pubsub-advanced-publisher     +3
#   Round 2486  ext-pubsub-advanced-history       +3
#   Round 2487  ext-pubsub-advanced-recovery      +3
#   Round 2488  ext-pubsub-advanced-subscriber    +1
#   Round 2490  session-matching                  +3
#
# DERIVED, not reconstructed from memory: every store commit in the window was
# replayed and these thirteen atoms' counts recomputed at each, by the same
# rule `citation_audit` uses. The method validates against this block itself --
# recomputing at the commit that last set the pin returns exactly 315 -- and
# the fifteen deltas sum to exactly 31, so nothing is unaccounted for.
# ⚠ ONE INFERENCE IS FLAGGED RATHER THAN HIDDEN: nine of the fifteen commits
# carry their round's own ledger key, and six changed the store WITHOUT filing
# an entry in the same commit. Those six are attributed to the first
# `docs(atomic): file Round N` commit that follows them, which is an inference
# from commit ORDER rather than a key read out of the blob.
#
# AMBIGUOUS HELD AT 73 for the fifth round running, and this time it held
# across fifteen rounds nobody was watching -- as did reached 55, unreached 3
# and no-symbol 2. Only the wz count moved, which is what a stretch of
# re-declaration rounds should do to it.
#
# R2541 (open-debt item 720) — 55 -> 54, and the three falls below are ONE
# EVENT: R2539 took `session-unicast-open` PARTIAL -> COMPLETE, so the atom left
# this census's population and took its citations with it. A count that falls
# because an atom was BUILT is the north star's own oracle moving; the pin owes
# it a move in the same commit, which R2539 did not make and hosted CI caught
# three times (run 34540131144, both C0 jobs and Layer Z).
#
# ⛔ DERIVED, not inferred from the commit subject. The R2538 store blob was
# read back out of git and this atom's reason re-audited AT THAT COMMIT by the
# same `citation_audit` the gate runs: it held wz=17 and ambiguous=2 there, and
# the pins fell by exactly 17 and 2. `reach_partition` puts the survivors at
# 54/3/2 against a population of 59, so `unreached` and `no_symbol` are
# untouched and only the reached bucket lost a member.
# ⚠ THE ATOM'S CURRENT REASON HOLDS wz=20, NOT 17, and the difference is not
# noise: R2539's last commit ("resolve the three doc links this round added")
# put three more citations into the same reason after this census had last
# passed. Reading today's text would have said the fall should be 20 and left
# three unaccounted for -- the count that matters is the one the reason held
# when the pin was last green.
#
# R2544b (the `liveliness-token` build) — 54 -> 53, the SAME EVENT SHAPE as the
# move above and paid in the SAME COMMIT this time. That atom went PARTIAL ->
# COMPLETE, so it left this census's population and took its citations with it.
#
# ⛔ R2541 had to pay this class as its own round because R2539 built an atom
# and did not move these pins; hosted CI then caught it in two C0 jobs. The
# lesson is cheap to state and was expensive to learn: BUILDING AN ATOM MOVES
# THIS CENSUS, so the build and the pin belong in one commit.
#
# DERIVED, not assumed: the pre-regrade reason was read back out of git at HEAD
# and re-audited by the same `citation_audit` the gate runs — wz=6, ambiguous=0,
# which is exactly what the two counts below fell by. `reach_partition` puts the
# survivors at 53/3/2 over a population of 58, so `unreached` and `no_symbol`
# are untouched and only the reached bucket lost its member.
#
# R2546 (the `attachment-bytes` build) — 53 -> 52, the same event shape a third
# time and paid in the same commit again. That atom went PARTIAL -> COMPLETE
# once its last clause was refuted by measurement and the carrier witnesses it
# lacked were built, so it left this population and took its citations with it.
#
# DERIVED the same way, and the arithmetic closes exactly rather than
# approximately: the HEAD blob's reason for that atom re-audited to wz=11,
# ambiguous=4, upstream=11, and it sat in the `reached` bucket — so the three
# pins below fall by 1, 11 and 4. Running the census against the stashed HEAD
# store reproduced 53 / 324 / 71 green, which is the other half of the same
# check: the fall is this atom's and no surviving atom's counts moved.
# ⚠ The NEW reason's own citations are not in any of these numbers and must not
# be looked for — a COMPLETE atom is outside this census's population, which is
# exactly why the count falls when one is built.
# R2548 (the `transport-link-vsock` build) — 52 -> 51. That atom went PARTIAL ->
# COMPLETE once its pin audit answered the four axes R2547 left open, so it left
# this population and took its citations with it. DERIVED: the HEAD blob's reason
# re-audited to wz=7, ambiguous=1, in the `reached` bucket.
PIN_REACHED = 51
PIN_UNREACHED = 3
PIN_NO_SYMBOL = 2
# R2534 — 346 -> 347. The atom is `adminspace-metrics` and the citation is the
# one R2533 added to its reason when the owner declined a gzip dependency: the
# reason now names `wz-session-core/src/adminspace.rs` as the file holding
# `metrics_encoding_never_claims_a_content_encoding`, the guard that keeps the
# encoding string from ever claiming a content-encoding wz cannot produce.
# A declined feature is recorded as a DIVERGENCE rather than a gap, and a
# divergence that names its guard is one a reader can check — which is exactly
# the kind of citation this ratchet counts.
#
# R2541 (open-debt item 720) — 347 -> 330 and 73 -> 71. Same event as the
# reached pin above: `session-unicast-open` completing removed the 17 wz and 2
# ambiguous citations its reason held at R2538. No surviving atom's citations
# moved, which is why the arithmetic closes exactly rather than approximately.
#
# R2544b — 330 -> 324, the six wz citations `liveliness-token`'s reason held
# while it was PARTIAL. AMBIGUOUS does NOT move: that atom held none, which the
# same re-audit says, so leaving 71 alone is a measurement rather than an
# omission.
#
# R2547 — 313 -> 315, and this one moves in the RISING direction, which is the
# ratchet doing what it exists for rather than an atom leaving. `transport-link-
# vsock` stayed PARTIAL and its reason gained two resolvable wz anchors while
# recording that its coverage residual is stale: `link_interfaces.rs` and
# `locator.rs`, named as two of the four axes its pin audit still owes. Derived
# by running `citation_audit` over the ADDENDUM ALONE -- wz=2, ambiguous=0 --
# so the rise is accounted for exactly and AMBIGUOUS correctly does not move.
#
# R2546 — 324 -> 313 and 71 -> 67. Same event as the reached pin above:
# `attachment-bytes` completing removed the 11 wz and 4 ambiguous citations its
# reason held at HEAD. AMBIGUOUS DOES move this time, unlike R2544b's, and the
# difference is a measurement rather than a habit — that reason cited four
# upstream paths whose basename also exists under `crates/`, which is what
# ambiguity means here.
# R2548 — 315 -> 309 and 67 -> 66, and this move has TWO terms rather than one,
# which is why it is written out: `transport-link-vsock` completing removed the
# wz=7 / ambiguous=1 its reason held, and the SAME round registered a sibling
# residual on `transport-link-serial` whose addendum adds wz=1 / ambiguous=0.
# Net -6 and -1, each half measured by running `citation_audit` over that text
# alone rather than inferred from the totals.
# R2550 — 309 -> 315, the RISING direction again and for the healthiest reason
# this ratchet has: `ext-pubsub-advanced-history` stayed PARTIAL and its reason
# gained six resolvable wz anchors while a pin-1.10.1 sweep recorded which of its
# clauses are stale, which axis is clean, and where the surviving build starts.
# Derived by auditing the ADDENDUM ALONE -- wz=6, ambiguous=0 -- so AMBIGUOUS
# correctly does not move and the rise is accounted for exactly.
# R2553 — 315 -> 326, the rising direction for the same healthy reason R2550
# gave, one round on: the `uhlc` late-publisher shape was BUILT, so
# `ext-pubsub-advanced-history` gained anchors on the code that now exists (the
# trigger, the GET, the reply-routing enum, the two witnesses) and
# `ext-pubsub-advanced-subscriber` gained two on the retention residual the
# build measured. Derived by auditing the TWO ADDENDA ALONE -- hist wz=9 /
# ambiguous=0, sub wz=2 / ambiguous=0 -- which is why AMBIGUOUS correctly does
# not move and 315 + 11 lands exactly on the 326 the census measures.
PIN_WZ_CITATIONS = 326
PIN_AMBIGUOUS = 66


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
