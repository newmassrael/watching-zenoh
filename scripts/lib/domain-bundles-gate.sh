#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R3335 (no register item) -- the DOMAIN-BUNDLE BUILD gate.
#
# ## The class, and why it needed a gate
#
# `domain_census.py` asks whether each `domain-*` bundle NAMES every atom of its
# namespace. Nothing asked whether a bundle COMPILES. Until R3335 no layer built
# one at all, so a bundle could list a combination the facade cannot build and
# the census, which reads names, stayed green.
#
# R3335 measured every bundle on a build host (`cargo check -p wz --features
# <bundle>`): 24 of 27 compile; three do not, and for ONE reason each -- the
# bundle lists atoms the facade refuses to link together, by a `compile_error!`
# in `crates/wz/src/lib.rs`:
#
#   domain-api       api-compat-c and api-compat-pico both export the `z_*` C
#                    symbols with different layouts
#   domain-platform  platform-freertos and platform-zephyr: one RTOS kernel and
#                    one #[global_allocator] per deploy
#   domain-runtime   runtime-tokio and runtime-coop: one runtime per deploy
#
# A domain bundle is a CENSUS of a namespace, and a namespace may hold
# alternatives (the same reason `storage-backend-*` are listed together). Those
# three are not defects; they are named exclusions, and the SET is pinned, not
# counted, as every gate here is.
#
# ## What this refuses
#
#   * a bundle that does not compile and is not an exclusion (a missing forward,
#     a guard that needs a companion atom, a platform-only atom);
#   * an exclusion that now COMPILES -- the guard went away or the bundle was
#     split, and the row would otherwise keep claiming a refusal that is gone;
#   * a population of zero bundles -- a derivation that matches nothing reports
#     on nothing.
#
# Usage:
#   domain-bundles-gate.sh            # every domain-* bundle of the wz facade
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../crates" || exit 2

# bundle -> the reason the facade refuses it. Pinned SET.
excluded="domain-api domain-platform domain-runtime"

meta="$(cargo metadata --no-deps --format-version 1 2>/dev/null)" || {
    echo "domain-bundles: FAIL -- cargo metadata did not run" >&2
    exit 1
}
bundles="$(printf '%s' "$meta" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
for p in d["packages"]:
    if p["name"] == "wz":
        for k in sorted(p["features"]):
            if k.startswith("domain-"):
                print(k)
')"

n=0
fail=0
for b in $bundles; do
    n=$((n + 1))
    if cargo check -p wz --features "$b" >/dev/null 2>&1; then
        built=1
    else
        built=0
    fi
    case " $excluded " in
    *" $b "*)
        if [ "$built" -eq 1 ]; then
            echo "  FAIL $b is an exclusion but now COMPILES -- drop it from \`excluded\`" >&2
            fail=1
        fi
        ;;
    *)
        if [ "$built" -eq 0 ]; then
            echo "  FAIL $b does not compile (cargo check -p wz --features $b)" >&2
            fail=1
        fi
        ;;
    esac
done

for e in $excluded; do
    case "
$bundles
" in
    *"
$e
"*) ;;
    *)
        echo "  FAIL exclusion $e names no domain bundle of the facade" >&2
        fail=1
        ;;
    esac
done

if [ "$n" -eq 0 ]; then
    echo "domain-bundles: FAIL -- the derivation found ZERO domain bundles" >&2
    exit 1
fi
if [ "$fail" -ne 0 ]; then
    echo "domain-bundles: FAIL" >&2
    exit 1
fi
echo "domain-bundles: OK -- $n bundle(s), $(printf '%s\n' $excluded | wc -l | tr -d ' ') named exclusion(s) (compile_error! by design), the rest compile"
