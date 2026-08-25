#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# install-mnemosyne-cli.sh — install the PINNED mnemosyne-cli for CI.
#
# Single source of truth for the mnemosyne-cli install, shared by
# .github/workflows/ci.yml and release.yml (mirrors run-ci.sh being the
# single source of truth for the lane logic) so the two workflows cannot
# drift.
#
# Pinned to a known-good rev (NOT `--branch main`): the install is then
# DETERMINISTIC — a future upstream mnemosyne `main` change cannot silently
# break this repo's CI (e.g. a config-schema change that rejects the current
# mnemosyne.toml). Bump MNEMOSYNE_REV deliberately, in its own commit, when
# this repo adopts a mnemosyne feature that needs a newer CLI; keep it in
# step with the locally-installed `--path` binary so local pre-push and CI
# validate against the same mnemosyne version.
#
# `--force` always rebuilds the pinned rev, overriding any stale
# ~/.cargo/bin binary a CI cache restored (Swatinem/rust-cache caches
# ~/.cargo/bin by default; without --force a `command -v` guard would run a
# stale cached CLI — the R408 `missing field docs` failure mode).
#
# READ, NOT SOURCED (R311y418): scripts/lib/schema-pin-gate.sh, used by both
# .githooks/pre-commit and .githooks/pre-push, extracts BOTH constants below
# textually from a git object, with line-anchored patterns. It deliberately
# does not source this file — that would execute an installer inside a git
# hook, which the first cut of R311y418 briefly did. So each assignment must
# stay on ONE unindented line in the literal form NAME="<value>", appearing
# exactly once; the gate hard-fails on any other count rather than guessing,
# and rejects a leading zero (bash `(( ))` reads 043 as octal).

set -euo pipefail

# github.com/newmassrael/mnemosyne @ d7f048b5 (a PUSHED origin/main rev), whose
# CLI defines CURRENT_SCHEMA_VERSION 43 and READS the schema-43 store.
#
# R311y417 REQUIRED bump, and the SECOND time this exact trap has fired (the
# R311y406 account it replaces is kept below). The R311y416 ledger append
# migrated the store 42 -> 43, so the prior pin b95b45d0 (max 42) rejected it:
# "schema version mismatch: store=43 expected ≤ 42" — Layer A red on run
# 30235292100, taking A2/A3/A4/B/B2 down as skipped with it. A reader whose max
# < store cannot lazy-migrate, so the pin must move UP to a reader that covers
# the store. Verified before landing: a d7f048b5 build validates this workspace
# clean (entries 1423, orphan new=+0).
#
# HOW IT FIRED, because the mechanism is what recurs: the session verified at
# kickoff that the PATH CLI (08e71f08) and the pin were both schema 42, and
# reported no trap. Correct then, stale later — the PATH binary was replaced
# mid-session by a 376c5e10-dirty build from parallel mnemosyne work carrying
# schema 43. So check `mnemosyne-cli --version` against this pin IMMEDIATELY
# BEFORE EVERY mutate, not once per session.
#
# DOCTRINE DEVIATION, disclosed: the paragraph this replaces required the pin to
# be "the exact locally-installed binary". It is not, this time. The local
# binary is 376c5e10-dirty — an uncommitted build, so unpinnable by
# construction, since CI resolves `--rev` from github. d7f048b5 is origin/main
# and carries the same CURRENT_SCHEMA_VERSION 43, which is the property that
# actually gates CI. Reinstalling the local CLI from d7f048b5 would restore the
# stricter invariant; it was left alone to avoid clobbering in-progress work.
#
# --- R311y429: d7f048b5 -> b867bfe2 (R786). NOT a schema bump ---
# The FIRST bump here driven by a new VALIDATOR rather than a schema migration,
# and the ceiling deliberately does not move: CURRENT_SCHEMA_VERSION is 43 at
# both revs (read at b867bfe2, not inherited — crates/mnemosyne-atomic/src/lib.rs
# :1678) and the store is 43. The co-change gate permits this direction; it
# refuses only a CEILING that moves while the rev stands still.
#
# WHY MOVE AT ALL, since nothing was red on CI: mnemosyne Round 783 added the
# citation-gate coverage check, which FAILS any workspace whose Rust trees are
# neither scanned nor declared. The author's PATH binary carried it while this
# pin did not, so `validate-workspace` reded in the pre-commit hook while hosted
# CI (which installs THIS rev) stayed green — the inverse of the usual failure
# and just as misleading. R311y429 adopts the gate's config
# (mnemosyne.toml [plugins.set_equality_validator]) and moves the pin in the
# SAME round, because a config the pinned reader cannot parse is a red of its
# own: SetEqualityValidatorConfig is #[serde(deny_unknown_fields)].
#
# The doctrine deviation disclosed below is REPAIRED by this bump: b867bfe2 is
# both origin/main upstream AND the exact rev the local PATH binary reports, so
# pin, local reader and CI reader are one rev again.
#
# --- the R311y406 precedent this bump follows (kept verbatim) ---
# The R311y406 store mutations (this repo's own commits, with the same
# b95b45d0 CLI locally) migrated the store 41 -> 42, and the prior pin (R311y403,
# d9e2beed) defines only schema <= 41, so its validate-workspace rejected the
# schema-42 store ("schema version mismatch: store=42 expected <= 41") — the
# Layer A red on the R311y406 hosted CI run.
# R311y436 — moved b867bfe2 -> 25d30d16 because a locally-installed CLI at
# 25d30d16 migrated the store 43 -> 44 during a routine ledger append, which the
# b867bfe2 reader cannot open ("schema version mismatch: store=44 expected <=
# 43"). That is the FIFTH occurrence of the shape enumerated below, and the
# first caught locally rather than on hosted CI — the schema-pin gate fired at
# validate-workspace instead of in Layer A. The rev is taken from cargo's own
# install ledger (~/.cargo/.crates.toml records the full SHA), not from
# `--version`; see the new pin-vs-installed gate for why that distinction is
# load-bearing.
#
# R311y462 — moved 25d30d16 -> a886cd0f, and this bump is NOT schema-forced: it
# is what makes `mnemosyne.toml [tool] pin` safe to declare in the same commit.
# Upstream sent an unsolicited notice (mnemosyne R868/R871) reporting that this
# tree's gate RESULT changed twice in one day with nothing changed here, because
# a repo that declares no `[tool] pin` gets whatever binary was installed on the
# machine LAST. Measured here before acting: the PATH CLI had drifted to
# be4c1647 (R869) while this constant still said 25d30d16 (R807), so the hooks
# were already running a reader the repo does not name. `[tool] pin` turns that
# silent mismatch into a loud refusal — which is the point — but the key is
# parsed by EVERY mnemosyne binary that opens this workspace, and an older one
# dies on it at TOML parse. That was measured on an isolated copy, not inferred:
# 0c82ad73 (R858) and be4c1647 (R869) both KNOW the key and enforce it, while
# 25d30d16 — the rev this constant pinned, and the rev `mnemosyne-mcp` was
# actually installed at — fails with "TOML parse error ... [tool]". Since
# ci.yml:594 installs THIS constant and then validates with it, declaring the
# key without moving the rev would have red-ed every hosted job, and killed the
# agent-session MCP server (the CLAUDE.md `Connection closed` shape). Upstream's
# own escape hatch does not cover it: MNEMOSYNE_PIN_SKIP=1 is read AFTER the
# config parses. MNEMOSYNE_MAX_SCHEMA stays 44 because 44 is what the NEW rev
# reads (see below) — the pairing rule binds a ceiling that moves alone, not a
# rev that moves alone.
MNEMOSYNE_REV="183a17a5254f27a246ef20e858de1523e0088815"

# The pinned rev's CURRENT_SCHEMA_VERSION: the HIGHEST atomic-store schema this
# CLI can read. Verified at the pin, not inherited from prose —
# crates/mnemosyne-atomic/src/lib.rs:1678 at b867bfe2 defines it as 43 (43 at
# the prior d7f048b5 too, which is why R311y429 moves the rev alone), and
# :1924 rejects `on_disk_version > CURRENT_SCHEMA_VERSION` outright. A reader
# cannot lazy-migrate DOWN to an older store shape, so a local mutate that
# migrates the store past this number reds hosted Layer A and takes
# A2/A3/A4/B/B2 with it. That has now happened FOUR times, every time
# discovered only on hosted CI — R311y15 (store=23 expected <= 9), R311y401
# (store=41 expected <= 39, repaired at y403), R311y406 (42 vs 41) and
# R311y416 (43 vs 42, repaired at y417). R311y417's carry said "twice";
# enumerating the ledger rather than inheriting that number gives four.
#
# This constant exists so the local hooks can turn that hosted red into a local
# one: scripts/lib/schema-pin-gate.sh reads the number below out of a git
# object and refuses any commit (index) or push (pushed commits) whose store
# schema_version exceeds it. MNEMOSYNE_REV and MNEMOSYNE_MAX_SCHEMA are ONE
# fact in two forms — never move the rev without re-reading
# CURRENT_SCHEMA_VERSION at the new rev and moving this with it. That pairing
# is now gated twice over: pre-commit refuses a ceiling that moves while the rev
# stands still (the ceiling is that gate's ONLY oracle, so raising it alone
# merely silences it), and R311y419 closed the hole that pairing could not
# reach — that the ceiling is the pinned reader's REAL CURRENT_SCHEMA_VERSION
# and not a mis-read of upstream source. See the tail of this script.
# R311y436 — 43 -> 44, READ AT THE NEW REV rather than inferred from the store
# that forced the bump: crates/mnemosyne-atomic/src/lib.rs:1687 at 25d30d16
# defines `pub const CURRENT_SCHEMA_VERSION: u32 = 44`, and :1971 still rejects
# `on_disk_version > CURRENT_SCHEMA_VERSION`. Reading the constant matters even
# when the store already says 44, because the store proves only what some
# writer produced, never what the pinned READER accepts.
# R311y738 — MOVED to 46 with the rev, and re-read at the new rev rather than
# carried: `crates/mnemosyne-atomic/src/lib.rs:1782` at 183a17a5 defines
# `CURRENT_SCHEMA_VERSION: u32 = 46`, and the installed binary's own
# `describe-schema` answers 46 as well — asserted twice, inherited zero times.
#
# WHY THIS BUMP HAPPENED AT ALL, which is the part worth keeping: the shared
# `~/.cargo/bin/mnemosyne-cli` had already moved to 183a17a5 (schema 46) while
# this repo still pinned a886cd0f/44, and `.githooks/pre-commit` refused every
# commit until the two agreed. The store was still at 44, so nothing had been
# migrated past the pinned reader — the hook stopped it BEFORE the mutate that
# R311y401, y406 and y416 each let through.
MNEMOSYNE_MAX_SCHEMA="46"

cargo install --git https://github.com/newmassrael/mnemosyne \
  --rev "$MNEMOSYNE_REV" --bin mnemosyne-cli --force mnemosyne-cli

# R311y465 — ALSO place the build in the pin's per-revision root, so `[tool] pin`
# has something to DELEGATE to. Upstream (mnemosyne R872) reported the gap: the
# pin's contract is "if the PATH build is not the pinned rev, hand over to
# `$MN_ROOT/<pin>/bin`", and this script only ever populated the SHARED slot, so
# a green run meant "PATH happens to equal the pin" rather than "the pin is
# satisfiable". On this machine the shared slot moved TWICE in one day, so the
# drift case is routine, not hypothetical.
#
# COPY, and in THIS direction, for two reasons that are easy to get backwards:
#
#  1. NOT `--root` INSTEAD of `--force`. Three sites resolve the CLI through
#     `command -v mnemosyne-cli` — `.githooks/pre-commit`, `.githooks/pre-push`
#     (both HARD-FAIL on absence since R311y418) and verify-mnemosyne-pin.sh,
#     whose comment says it grades `command -v` precisely so a shadowing binary
#     is caught rather than bypassed. Moving the install out of the shared slot
#     would empty the path all three look at.
#  2. NOT `cargo install --root` as a SECOND install. That is a second build,
#     and — the part that matters — the shared slot's `~/.cargo/.crates.toml`
#     entry is what R311y436 established as the SSOT for reading the full pinned
#     SHA (`--version` is refused for that job). Keeping `cargo install` on the
#     shared slot keeps that ledger truthful; the per-rev root needs no ledger.
#
# A bare copy is sufficient by upstream's own design: the handover VERIFIES the
# target by asking it `--version` and refuses an unverifiable one
# (mnemosyne-config/src/lib.rs, Round 861), and `pinned_binary` is just
# `<root>/bin/<name>` — the `cargo install --root` layout read back. The
# directory name is the pin string VERBATIM (`pinned_root` joins it unmodified),
# which is why this uses "$MNEMOSYNE_REV" and not a shortened form.
_mn_shared_cli="${CARGO_HOME:-$HOME/.cargo}/bin/mnemosyne-cli"
_mn_pin_root="${MN_ROOT:-$HOME/.local/mn}/$MNEMOSYNE_REV"
if [ -x "$_mn_shared_cli" ]; then
    mkdir -p "$_mn_pin_root/bin"
    cp -f "$_mn_shared_cli" "$_mn_pin_root/bin/mnemosyne-cli"
    # Self-check the copy the way the handover will: `--version` stamps a short
    # `git describe` hash, and the pin is matched by PREFIX on the shorter of the
    # two. A copy that cannot answer for itself is worse than no copy, because
    # the handover would refuse it and name THIS path in the error.
    #
    # The EMPTY-stamp case is handled first and separately on purpose: a `case`
    # pattern built from an empty variable collapses to `*`, which matches
    # anything, so folding "unreadable" into the prefix test would silently turn
    # this self-check into a no-op — the hollow-gate shape R311y416/y417 kept
    # finding. Not knowing is refused, exactly as the handover refuses it.
    _mn_stamp="$("$_mn_pin_root/bin/mnemosyne-cli" --version 2>/dev/null \
        | sed -n 's/.*(\([0-9a-f]\{4,\}\)).*/\1/p')"
    if [ -z "$_mn_stamp" ]; then
        echo "install-mnemosyne-cli: FAIL — the copy at $_mn_pin_root/bin does not" >&2
        echo "  answer \`--version\` with a revision stamp, so the handover would" >&2
        echo "  refuse it as unverifiable and name this path in the error." >&2
        exit 1
    fi
    case "$MNEMOSYNE_REV" in
        "$_mn_stamp"*)
            echo "install-mnemosyne-cli: pin root ready — $_mn_pin_root/bin/mnemosyne-cli ($_mn_stamp)" ;;
        *)
            echo "install-mnemosyne-cli: FAIL — the copy at $_mn_pin_root/bin stamps" >&2
            echo "  '$_mn_stamp', which is not a prefix of the pinned" >&2
            echo "  $MNEMOSYNE_REV. The handover would refuse it and blame this path." >&2
            exit 1 ;;
    esac
else
    echo "install-mnemosyne-cli: FAIL — no binary at $_mn_shared_cli after" >&2
    echo "  \`cargo install --force\`; the shared slot is what the hooks resolve." >&2
    exit 1
fi

# R311y419 — ask the binary just installed what schema it actually reads, and
# refuse to hand a mismatched pin to the rest of the job.
#
# CALLED FROM HERE, not wired as a separate ci.yml step, so that it cannot be
# forgotten by a caller. This script exists because ci.yml and release.yml must
# not drift; a gate bolted onto one workflow would reintroduce exactly that
# drift, and a gate that is defined but not wired is the hollow-gate shape
# R311y416/y417 kept finding. Every route that installs the pinned CLI — both
# workflows, and any local `bash scripts/install-mnemosyne-cli.sh` — now runs
# it. Git hooks do NOT: they never install, so they still verify the store
# against the ceiling without ever verifying the ceiling itself.
#
# MNEMOSYNE_MAX_SCHEMA is passed in rather than re-parsed out of this file: the
# value compared is then the one that was actually used, and
# scripts/lib/schema-pin-gate.sh stays the single textual parser of these two
# constants. That in-script use is also why the SC2034 disable this assignment
# used to carry is gone — the constant is live code now, not inert text.
bash "$(dirname "${BASH_SOURCE[0]}")/verify-mnemosyne-pin.sh" "$MNEMOSYNE_MAX_SCHEMA"
