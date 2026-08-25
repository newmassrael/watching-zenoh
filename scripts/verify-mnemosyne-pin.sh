#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# verify-mnemosyne-pin.sh — prove the INSTALLED mnemosyne-cli really reads the
# schema that MNEMOSYNE_MAX_SCHEMA claims it reads (R311y419).
#
# WHY THIS EXISTS. scripts/lib/schema-pin-gate.sh (R311y418) grades the STORE
# against MNEMOSYNE_MAX_SCHEMA, and .githooks/pre-commit additionally refuses a
# ceiling that moves while MNEMOSYNE_REV stands still. Neither can check the one
# thing both of them depend on: that the ceiling is the pinned reader's REAL
# CURRENT_SCHEMA_VERSION. Both numbers are hand-set from a hand-read of upstream
# source. Get that read wrong — or bump the rev and copy the old number — and
# every other gate is grading against a fiction while hosted Layer A reds
# exactly as if no gate existed. R311y418's own carry named this as the honest
# next step and placed it "beside the cargo install --rev", because verifying it
# needs the pinned build itself.
#
# THE ORACLE is `mnemosyne-cli describe-schema --json` -> .schema_version, which
# mnemosyne-ops::describe_schema() populates from
# mnemosyne_atomic::CURRENT_SCHEMA_VERSION and documents as "Pure — no store, no
# order, no I/O" (mnemosyne crates/mnemosyne-validate/src/schema.rs:264-267 at
# d7f048b5). Confirmed pure by construction rather than by that comment: it
# reports 43 with no workspace present at all, and 43 unchanged against a store
# hand-set to schema_version 999. So it is a property of the BINARY and never of
# the tree it runs in — which is what makes it a valid oracle for the number
# that decides what the binary can open.
#
# GRADING THE BINARY, NOT THE SOURCE, is deliberate. Reading
# crates/mnemosyne-atomic/src/lib.rs out of ~/.cargo/git/checkouts would grade a
# file that need not be what `cargo install` actually built. The installer's own
# `--force` guards the same seam from the other side — Swatinem/rust-cache
# caches ~/.cargo/bin, so a `command -v` guard there would run whatever binary
# the cache restored. (That comment describes a failure MODE and names the shape
# it would take, a mnemosyne-R408 `missing field docs`; it does not record an
# occurrence, and neither this ledger nor that script claims one. Do not
# upgrade it to a war story.) Asking the installed binary rather than a source
# file means a stale binary that disagrees with the pin is caught here even if
# --force were ever weakened.
#
# WHICH binary: whatever `command -v mnemosyne-cli` resolves to, because that is
# what every later CI step runs. Grading the just-written
# $CARGO_HOME/bin/mnemosyne-cli instead would miss a shadowing earlier-PATH
# binary that Layer A would actually use.
#
# WHAT THIS DELIBERATELY DOES NOT GATE: that the binary was built from
# MNEMOSYNE_REV. `mnemosyne-cli --version` embeds `git describe --always
# --dirty=-dirty --abbrev=8` (mnemosyne crates/mnemosyne-cli/build.rs:10-23), so
# it is a bare short hash only while NO tag is reachable upstream — the day
# mnemosyne tags a release it becomes `v1.2.3-5-g<hash>` — and it degrades to
# the literal `unknown` when .git is absent. That is a gate whose truth depends
# on another project's tagging policy and on how cargo materialises a checkout.
# The schema number depends on neither, and it is the exact quantity that
# decides whether hosted Layer A can open the store. Do not "strengthen" this
# into a version-string match.

set -euo pipefail

fail() {
    echo "verify-mnemosyne-pin: $*" >&2
    exit 1
}

if [[ $# -ne 1 ]]; then
    fail "usage: verify-mnemosyne-pin.sh <expected-schema>

  Called from the tail of scripts/install-mnemosyne-cli.sh with that script's
  own MNEMOSYNE_MAX_SCHEMA. The caller owns the constant — passing it in rather
  than re-parsing the pin script means this gate compares the value that was
  actually used to install, and keeps the text contract in
  scripts/lib/schema-pin-gate.sh as the single parser."
fi

expected="$1"

# Same grammar the hook-side parser accepts (scripts/lib/schema-pin-gate.sh):
# bounded, and no leading zero. The comparison below is a STRING equality, so
# octal cannot bite here the way it did in R311y418's `(( ))` — but a ceiling
# written "043" must still be named as malformed rather than reported as a
# mismatch against 43, which would send the reader hunting the wrong bug.
if [[ ! "$expected" =~ ^(0|[1-9][0-9]{0,5})$ ]]; then
    fail "expected-schema '${expected}' is not a bare decimal (no leading zero,
  at most 6 digits). Fix MNEMOSYNE_MAX_SCHEMA in
  scripts/install-mnemosyne-cli.sh — scripts/lib/schema-pin-gate.sh rejects the
  same shape, so the local hooks are already failing on it too."
fi

if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 not on PATH — needed to parse \`describe-schema --json\`.
  This is a hard failure, not a skip: a gate that cannot read its input must
  not report green."
fi

if ! cli="$(command -v mnemosyne-cli)"; then
    fail "mnemosyne-cli is not on PATH after the pinned install.
  Nothing later in this job could run Layer A either, so there is no version of
  this that is merely a warning. Check that \$CARGO_HOME/bin is on PATH."
fi

# 2>&1 so an upstream rename of the subcommand is quoted back to the maintainer
# rather than swallowed. A future pin that drops `describe-schema` must red here
# and be re-pointed at whatever replaced it — never silently stop checking.
if ! raw="$(mnemosyne-cli describe-schema --json 2>&1)"; then
    fail "\`mnemosyne-cli describe-schema --json\` failed on ${cli}:

${raw}

  If the subcommand was renamed or removed upstream, this gate must be
  re-pointed at the new way to ask a mnemosyne-cli for its
  CURRENT_SCHEMA_VERSION. Do not delete the check."
fi

if ! actual="$(printf '%s' "$raw" | python3 -c '
import json, sys

version = json.load(sys.stdin).get("schema_version")
if isinstance(version, bool) or not isinstance(version, int):
    sys.exit("schema_version absent or not an integer")
print(version)
' 2>/dev/null)"; then
    fail "cannot read .schema_version from \`describe-schema --json\` on ${cli}
  — malformed JSON, or the key is missing / not an integer. The oracle's shape
  changed; re-point this gate rather than removing it."
fi

if [[ "$actual" != "$expected" ]]; then
    fail "the pinned mnemosyne-cli does NOT read the schema the pin claims.

    binary            ${cli}
    reports           CURRENT_SCHEMA_VERSION = ${actual}
    pin claims        MNEMOSYNE_MAX_SCHEMA   = ${expected}

  MNEMOSYNE_REV and MNEMOSYNE_MAX_SCHEMA are one fact in two forms, and this is
  the only check that reads the fact from the rev instead of from prose. With
  them disagreeing, every other schema gate is grading against a number the
  installed reader does not honour:

    - ceiling ABOVE the real value  ->  the store-vs-ceiling gate passes stores
      this binary cannot open, and hosted Layer A reds with
      \"schema version mismatch\", skipping A2/A3/A4/B/B2 behind it. This is the
      failure the whole pin exists to prevent, re-armed by a wrong constant.
    - ceiling BELOW the real value  ->  no hosted red, but the local hooks
      refuse commits and pushes that are in fact fine, and the pin bump that
      would unblock them looks unnecessary.

  fix: read CURRENT_SCHEMA_VERSION at MNEMOSYNE_REV
       (crates/mnemosyne-atomic/src/lib.rs in the mnemosyne repo) and set
       MNEMOSYNE_MAX_SCHEMA in scripts/install-mnemosyne-cli.sh to ${actual},
       or move MNEMOSYNE_REV to the rev that really defines ${expected}."
fi

echo "verify-mnemosyne-pin: OK — ${cli} reads schema ${actual}, matching MNEMOSYNE_MAX_SCHEMA."
