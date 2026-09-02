#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# check-capi-c-opaque-arms.sh — measure ALL FOUR §5.27 api-compat-c ABI arms
# against upstream's own opaque-type generator (R311y540).
#
# ## Why this exists
#
# Layer C1cc's footprint leg compares wz against the INSTALLED `zenoh_opaque.h`.
# That header exists for exactly ONE feature arm — whichever build the machine
# provisioned — and `install-zenoh-c.sh` provisions the published standalone
# archive, which R2278 measured to be the `unstable-shm` build. wz's DEFAULT
# feature set models the `unstable` arm, so the arm wz selects by default is
# still not the one any installed header describes, and that is where a 40-byte
# `z_owned_bytes_t` sat unchallenged from R311y498 to R311y540: a size no
# zenoh-c 1.5.0 build has, on an arm nothing looked at.
#
# The fix is to stop needing an installed header. zenoh-c GENERATES its opaque
# header from `build-resources/opaque-types`, a crate whose entire purpose is to
# fail compilation with `type: X, align: N, size: M` per type. Building it with a
# chosen feature set yields the size table for a build nobody has to install —
# so every arm becomes measurable from one source checkout.
#
# There are FOUR, not two: `Z_FEATURE_UNSTABLE_API` and `Z_FEATURE_SHARED_MEMORY`
# are independent axes whose deltas ADD. That was itself the finding — the 40
# this crate had attributed to unstable since R311y498 is the SHARED-MEMORY
# number, and shared-memory moves 8 of the types wz declares against unstable's
# 2. Checking only the unstable axis would have missed the one that was wrong.
#
# ## Two variables had to be removed before the generator was an oracle
#
# Calibration, not assumption: the arm the installed oracle actually IS — read
# off its own `zenoh_configure.h` since R311y566, not fixed at `nounstable` as
# this paragraph used to say — must reproduce the installed `zenoh_opaque.h`
# EXACTLY, and getting there took pinning two things.
#
#   1. The FEATURE LIST. Passed explicitly below as `BASE_FEATURES`, which is
#      what the installed `zenoh_configure.h` declares APART from the two axis
#      features each arm adds; R2278 renamed it, because a base list that
#      claimed to be the whole list is a list that cannot be checked against
#      the header it names. (Measured: this turned out NOT to matter —
#      `zenoh/default` gives an identical table — but it is pinned anyway,
#      because "it did not matter on the machine I checked" is not a contract.)
#   2. The TOOLCHAIN. This one DID matter: `z_owned_task_t` is 32 bytes under
#      zenoh-c's pinned 1.85.0 and 24 under 1.97.0, and that single type was the
#      whole gap between 61/62 and 62/62. The channel is read out of the
#      checkout's own `rust-toolchain.toml` rather than hardcoded here.
#
# ## Cost, and why it is not in the default lane set
#
# A cold run builds the zenoh dependency graph once per arm — minutes,
# and it needs network for zenoh-c's git dependency on zenoh. Re-runs are
# incremental against `target/zenoh-c-opaque/`. It is therefore an on-demand
# provisioning check like `build-zenohd.sh`, wired into Layer C1cc behind
# WZ_C1CC_OPAQUE_ARMS=1 rather than run on every push.
#
# Absent checkout => SKIP with a LOUD note, because a silent skip is a green
# that proved nothing. WZ_CAPI_C_ARMS_REQUIRE=1 turns the skip into a failure.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REF="${WZ_ZENOH_C_REF:-$HOME/zenoh-c-ref}"
OUT="$ROOT/target/zenoh-c-opaque"
MANIFEST="$REF/build-resources/opaque-types/Cargo.toml"

say() { printf '[capi-c-opaque-arms] %s\n' "$*"; }

if [[ ! -f "$MANIFEST" ]]; then
    if [[ -n "${WZ_CAPI_C_ARMS_REQUIRE:-}" ]]; then
        say "FAIL — required (WZ_CAPI_C_ARMS_REQUIRE set) but zenoh-c's SOURCE"
        say "       checkout is absent. This needs the repository, not the release"
        say "       archive: git clone --depth 1 --branch 1.10.0 \\"
        say "       https://github.com/eclipse-zenoh/zenoh-c $REF"
        exit 1
    fi
    say "SKIP — zenoh-c's SOURCE checkout is absent at $REF."
    say "       The release archive install-zenoh-c.sh provisions does NOT carry"
    say "       build-resources/opaque-types, so this check needs the repo:"
    say "       git clone --depth 1 --branch 1.10.0 \\"
    say "       https://github.com/eclipse-zenoh/zenoh-c $REF"
    exit 0
fi

# The toolchain zenoh-c itself builds with, read from the checkout so a pin bump
# upstream moves this check with it instead of silently measuring a different
# layout.
CHANNEL="$(sed -n 's/^ *channel *= *"\([^"]*\)".*/\1/p' "$REF/rust-toolchain.toml" | head -1)"
if [[ -z "$CHANNEL" ]]; then
    say "FAIL — could not read the pinned channel from $REF/rust-toolchain.toml."
    say "       Measuring under an arbitrary toolchain is what this check exists"
    say "       to avoid; refusing rather than guessing."
    exit 1
fi
if ! rustup toolchain list 2>/dev/null | grep -q "^${CHANNEL}"; then
    if [[ -n "${WZ_CAPI_C_ARMS_REQUIRE:-}" ]]; then
        say "FAIL — zenoh-c pins toolchain $CHANNEL and it is not installed."
        say "       rustup toolchain install $CHANNEL"
        exit 1
    fi
    say "SKIP — zenoh-c pins toolchain $CHANNEL, which is not installed."
    say "       rustup toolchain install $CHANNEL"
    exit 0
fi
say "upstream pins toolchain $CHANNEL"

# The NON-AXIS part of the feature list: what the published package declares
# MINUS the two features the four arms below add. It is not the package's whole
# list and R2278 renamed it for saying it was — the package carries
# `Z_FEATURE_SHARED_MEMORY` and `Z_FEATURE_UNSTABLE_API` too, and adding them
# here would make every arm the same build. See the header for why the base is
# pinned even though it measured as not mattering.
BASE_FEATURES=(
    -F auth_pubkey -F auth_usrpwd -F transport_multilink -F transport_quic
    -F transport_tcp -F transport_tls -F transport_udp
    -F transport_unixsock-stream -F transport_ws
)

mkdir -p "$OUT"

# Generate one arm's size table. `-F panic` is what makes the crate emit the
# sizes as compilation errors, so a NON-ZERO exit is the SUCCESS path here and
# the record count below is the real verdict.
generate() {
    local arm="$1"; shift
    if [[ -s "$OUT/$arm.stderr" ]] \
       && grep -qE 'type: \w+, align: [0-9]+, size: [0-9]+' "$OUT/$arm.stderr"; then
        say "$arm: reusing $OUT/$arm.stderr"
        return 0
    fi
    say "$arm: generating (cold runs build the zenoh graph; this takes minutes)"
    cargo "+$CHANNEL" build -F panic --no-default-features "$@" --locked \
        --manifest-path "$MANIFEST" --target-dir "$OUT/$arm" \
        2> "$OUT/$arm.stderr"
    local n
    n="$(grep -cE 'type: \w+, align: [0-9]+, size: [0-9]+' "$OUT/$arm.stderr" || true)"
    if [[ "$n" -eq 0 ]]; then
        say "FAIL — the $arm generator run produced NO size records. Its stderr"
        say "       is at $OUT/$arm.stderr; the usual cause is a dependency that"
        say "       does not build under $CHANNEL."
        return 1
    fi
    say "$arm: $n size records"
}

# FOUR arms, because `Z_FEATURE_UNSTABLE_API` and `Z_FEATURE_SHARED_MEMORY` are
# INDEPENDENT axes and R311y540 measured both: 8 of the types wz declares move
# with shared-memory, 2 move with unstable, and 2 move with each (additively).
# Checking only the unstable axis would leave the one that was actually wrong.
rc=0
generate nounstable "${BASE_FEATURES[@]}" || rc=1
generate unstable "${BASE_FEATURES[@]}" -F unstable || rc=1
generate nounstable-shm "${BASE_FEATURES[@]}" -F shared-memory || rc=1
generate unstable-shm "${BASE_FEATURES[@]}" -F unstable -F shared-memory || rc=1
[[ $rc -eq 0 ]] || exit 1

# CALIBRATION FIRST. ONE generator arm must reproduce the INSTALLED header
# exactly; if it does not, the generator is not describing the same build the
# rest of the lane measures against and its OTHER tables cannot be trusted
# either. Checking the arm we can verify is what licenses the arms we cannot.
#
# R311y566 — WHICH arm is READ OFF THE ORACLE, not assumed. This calibrated the
# `nounstable` table unconditionally, which is blind on any machine whose
# installed zenoh-c is a different build: the author's `~/.local` then held a
# plain `nounstable` install and the arm matched, while hosted CI provisions an
# unstable+SHM oracle where that arm CANNOT match and never could. (R2278: that
# install was not the published package, which is the `unstable-shm` build.)
# So the job redded on a calibration structurally unable to pass, and the
# four-arm comparison below it -- the whole point of the script -- has not run on
# hosted since R311y542.
#
# The fix is the technique the census gate already uses: the oracle ships its own
# `zenoh_configure.h`, so the arm is a fact to read rather than a default to
# guess.
PREFIX="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"
INCLUDE="$PREFIX/include"
CALIBRATION_ARM=""
if [[ -f "$INCLUDE/zenoh_configure.h" ]]; then
    # The SHARED resolver, not an inlined copy — `test-zenoh-c-oracle-arm.sh`
    # drives this exact file on all four combinations plus the refusal case, and
    # a probe against a copy would prove nothing about what ships.
    CALIBRATION_ARM="$(bash "$ROOT/scripts/lib/zenoh-c-oracle-arm.sh" "$PREFIX")"
    say "installed oracle is the '$CALIBRATION_ARM' build"
elif [[ -f "$INCLUDE/zenoh_opaque.h" ]]; then
    say "FAIL — the installed oracle has zenoh_opaque.h but no zenoh_configure.h,"
    say "       so which build it is cannot be established. Calibrating against a"
    say "       guessed arm is what made this gate structurally unpassable on"
    say "       hosted CI; it is not repeated."
    exit 1
fi
if [[ -n "$CALIBRATION_ARM" && -f "$INCLUDE/zenoh_opaque.h" ]]; then
    if ! python3 - "$INCLUDE/zenoh_opaque.h" "$OUT/$CALIBRATION_ARM.stderr" <<'PY'
import re, sys
hdr, gen = sys.argv[1], sys.argv[2]
installed = {m.group(2): int(m.group(3)) for m in re.finditer(
    r'typedef struct ALIGN\((\d+)\)\s+(\w+)\s*\{\s*\w+\s+\w+\[(\d+)\];\s*\}\s*\2;',
    open(hdr).read())}
table = {m.group(1): int(m.group(3)) for m in re.finditer(
    r'type: (\w+), align: (\d+), size: (\d+)', open(gen).read())}
common = sorted(set(installed) & set(table))
bad = [(t, installed[t], table[t]) for t in common if installed[t] != table[t]]
print(f"[capi-c-opaque-arms] calibration: {len(common)} type(s) shared with the "
      f"installed header, {len(bad)} disagree")
for t, i, g in bad:
    print(f"  CALIBRATION MISMATCH {t}: header={i} generator={g}", file=sys.stderr)
sys.exit(1 if bad or not common else 0)
PY
    then
        say "FAIL — the '$CALIBRATION_ARM' generator arm does NOT reproduce the"
        say "       installed header, and that IS the arm this oracle claims to be."
        say "       Until it does, every other arm's table describes some other"
        say "       build and comparing wz against them would be theatre."
        exit 1
    fi
else
    say "no installed zenoh_opaque.h — calibration skipped (the comparison below"
    say "still runs, but nothing has confirmed the generator matches this machine)"
fi

# Build each wz arm and compare it against ITS OWN table. Serial and to the same
# artifact path on purpose: the four builds differ only in features, so cargo
# rebuilds just this crate each time, and comparing immediately after each build
# keeps the cdylib and the table paired.
check_arm() {
    local table="$1" label="$2"; shift 2
    (cd "$ROOT/crates" && cargo build -p wz-capi-c "$@" --quiet) || return 1
    python3 "$ROOT/scripts/lib/capi_c_opaque_arms.py" \
        --generator-stderr "$OUT/$table.stderr" \
        --cdylib "$ROOT/crates/target/debug/libwz_capi_c.so" \
        --arm "$label"
}

check_arm unstable      "default (unstable, no shm)"        || rc=1
check_arm nounstable    "no-unstable"                       \
    --features zenoh-c-no-unstable-api                      || rc=1
check_arm unstable-shm  "unstable + shared-memory"          \
    --features zenoh-c-shared-memory                        || rc=1
check_arm nounstable-shm "no-unstable + shared-memory"      \
    --features zenoh-c-no-unstable-api,zenoh-c-shared-memory || rc=1

exit $rc
