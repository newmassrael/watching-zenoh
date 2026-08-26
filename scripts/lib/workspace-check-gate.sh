#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R2134 (no register item) — the WORKSPACE TYPE-CHECK gate. The debt it closes
# is item 475 in the UNREGISTERED set, which has no store `debt-` id.
#
# ## The class
#
# Widening a public struct breaks the crates that CONSTRUCT it, and pre-push
# tests only the crates a push CHANGES. So the round that widens the struct is
# green locally and the dependent crate stops compiling on hosted CI.
#
# It has happened TWICE with the same struct. R311y857 added a field to
# `wz_analyze::Request` and left `wz-replay`'s initializer behind; R2001 did it
# again with `csv`, and hosted Layer C1 died on `error[E0063]: missing field`.
# The second time, the fixing session was looking at a PARAGRAPH inside that
# very initializer explaining that this had already happened once. A comment is
# not a gate — the same lesson R1994 recorded as the discovery floor.
#
# ## Why `check --workspace` and not one of the obvious candidates
#
# The owner decided this on 2026-08-24, and the reasoning is about the SHAPE OF
# THE FAILURE: the red is `error[E0063]`, a COMPILE error, not a test failure,
# so the instrument must measure the same thing that breaks. Checking only
# DIRECT dependents is an arbitrary cut that misses indirect ones; leaving it to
# hosted CI is not a hypothesis any more, because the round-per-recurrence bill
# has now been paid twice.
#
# It does not contradict R311y386's ratification of pre-push as a FAST gate
# rather than a CI mirror. That ratification is about not running the TEST
# SUITE; `check` is type-checking, not test execution. And
# `doclink_dependents.py`'s warning that a core crate's reverse dependencies are
# nearly the whole workspace is not an objection here — it is the REASON, since
# that is exactly the blast radius of widening a core type.
#
# ## Why the exclusions are READ and never copied
#
# Four members cannot take part in a workspace build: feature unification drives
# them into a `compile_error!` (the multicast-only Session API sits behind
# `not(transport-unicast)`) or they are MCU targets. Layer C1 already carries
# that list, and duplicating it here would make this file go stale the moment
# that list moves — open-debt item 47 is the register of exactly that decay. So
# the list is PARSED out of Layer C1's own invocation, and a parse that finds
# nothing is a hard failure rather than a run with no exclusions at all.
#
# ## `--all-targets`, deliberately
#
# The measured red was in a BINARY (`wz-replay/src/main.rs`), but the same class
# sits in test-code initializers. Leaving `--all-targets` off would silently
# skip that half.
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1
RUNCI="scripts/run-ci.sh"

if [[ ! -f "$RUNCI" ]]; then
    echo "  workspace-check FAIL: cannot read $RUNCI, which is where the" \
         "exclusion list is read from" >&2
    exit 1
fi

# The excludes belonging to Layer C1's `cargo test --workspace` invocation, and
# only that one. Anchored on the invocation rather than on a line number: item
# 475 cited `run-ci.sh:3159-3163` and by the time it was repaid that range held
# a different layer entirely.
read -r -d '' extract_py <<'PY'
import re
import sys

src = sys.stdin.read()
m = re.search(
    r"\(\s*cd crates && cargo test --workspace\b(?P<flags>.*?)\)",
    src,
    re.S,
)
if m is None:
    sys.exit("NOFIND")
names = re.findall(r"--exclude\s+([A-Za-z0-9_-]+)", m.group("flags"))
if not names:
    sys.exit("NOEXCLUDE")
print("\n".join(names))
PY

if ! mapfile -t excludes < <(python3 -c "$extract_py" <"$RUNCI"); then
    :
fi
if [[ ${#excludes[@]} -eq 0 ]]; then
    echo "  workspace-check FAIL: could not read Layer C1's" \
         "\`(cd crates && cargo test --workspace …)\` invocation out of" \
         "$RUNCI, or it carries no --exclude. Running the workspace WITHOUT" \
         "those exclusions does not fail honestly — feature unification drives" \
         "four members into a compile_error! — so this gate refuses rather" \
         "than reporting a red it caused itself. Re-anchor this parse on" \
         "whatever that invocation looks like now." >&2
    exit 1
fi

args=(check --workspace --all-targets --quiet)
for pkg in "${excludes[@]}"; do
    args+=(--exclude "$pkg")
done

echo "  workspace-check: cargo check --workspace --all-targets, excluding" \
     "${#excludes[@]} member(s) read from Layer C1 (${excludes[*]})"
if ! (cd crates && cargo "${args[@]}"); then
    echo "  workspace-check FAIL: the workspace does not type-check. A crate" \
         "the push did not CHANGE no longer compiles — the usual cause is a" \
         "public struct that grew a field while an initializer somewhere else" \
         "kept the old shape. pre-push tests only changed crates, which is why" \
         "this gate exists (open-debt item 475, twice measured)." >&2
    exit 1
fi
echo "  workspace-check: the workspace type-checks"
exit 0
