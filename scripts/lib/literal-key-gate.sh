#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y820 (no register item) — the LITERAL COOKIE SIGNING KEY gate. The debt it
# closes lives in the UNREGISTERED set (item 105, the second half of item 88),
# not in the store's `debt-` inventory, so there is no register id to cite.
#
# ## What it refuses, and why it exists
#
# `SessionInitParams::cookie_signing_key` is the key behind the
# anti-amplification cookie's HMAC. At R311y820 every params builder in this
# tree wrote it as a LITERAL — `vec![0xAB; 32]` in the AP demo, the C ABI drive
# and the replay live path, `vec![7u8; 32]` on the MCU acceptor — while
# `signing_key_from_os_entropy`, available since R69, had ZERO production
# callers. Those literals are committed to a PUBLIC repository, so the cookie
# key of every acceptor built from this tree was public knowledge.
#
# The class leaked at FOUR sites before anyone counted them, which is this
# project's own threshold for building a gate rather than fixing instances.
#
# ## The rule
#
# A `SigningKey::new(vec![...])` — construction from a literal — may appear
# only under a `tests/` directory (integration tests, which never ship) or in a
# file on the allowlist below, at exactly the recorded count. Everything else
# must reach a key through `SigningKey::from_entropy`, the §2.5 port.
#
# ## Why counts and not just paths
#
# A bare path allowlist would let a file that legitimately has one test key
# grow a second one that is NOT a test key. The count is watched in BOTH
# directions, like the C1bz doc budget: a rise is a new literal to justify, a
# fall is a removal that has to say so in the same commit.
set -uo pipefail

repo_root="${1:-.}"

# path:count — every entry is a `#[cfg(test)] mod tests` block or the
# test-support crate, i.e. a key that never reaches a shipped acceptor.
allow="
crates/wz-session-core/src/signing_key.rs:5
crates/wz-session-core/src/handshake_encode.rs:1
crates/wz-runtime-coop/src/session_runtime.rs:1
crates/wz-session-lwip/src/session_drive.rs:1
crates/wz-runtime-tokio-test-support/src/lib.rs:2
"

fail=0
declare -A seen=()

# Production sources only: `crates/*/src/**` and `deploy/**/src/**`. Files under
# a `tests/` directory are out of scope by construction — an integration test is
# not a shipped path, and pinning counts there would make every new test a gate
# edit for no security gain.
while IFS= read -r file; do
    count="$(grep -c 'SigningKey::new(vec!\[' "$file" 2>/dev/null || true)"
    [[ "${count:-0}" -gt 0 ]] || continue
    rel="${file#"$repo_root"/}"
    expected="$(grep -oE "^${rel}:[0-9]+$" <<<"$allow" | cut -d: -f2 || true)"
    if [[ -z "$expected" ]]; then
        echo "  literal-key FAIL: $rel constructs a SigningKey from a literal" \
             "(${count} site(s)). A shipped acceptor's cookie key must come from" \
             "SigningKey::from_entropy — a literal here is published with the repo."
        fail=1
        continue
    fi
    seen["$rel"]=1
    if [[ "$count" != "$expected" ]]; then
        if [[ "$count" -gt "$expected" ]]; then
            echo "  literal-key FAIL: $rel has $count literal key site(s), allowance $expected"
        else
            echo "  literal-key FAIL: $rel has $count literal key site(s) but the" \
                 "allowance still says $expected — lower it in this commit"
        fi
        fail=1
    fi
done < <(find "$repo_root/crates" "$repo_root/deploy" -type d -name tests -prune -o \
    -type f -name '*.rs' -path '*/src/*' -print 2>/dev/null)

# An allowance naming a file that no longer has the site is an allowance nobody
# is reading — the same reason the orphan ledger rejects a resolved entry.
while IFS= read -r row; do
    [[ -n "$row" ]] || continue
    path="${row%%:*}"
    if [[ -z "${seen[$path]:-}" ]]; then
        echo "  literal-key FAIL: the allowance names $path, which has no literal" \
             "key site (or no longer exists) — drop the row"
        fail=1
    fi
done <<<"$allow"

if [[ $fail -eq 0 ]]; then
    echo "  literal-key: no shipped path builds a cookie signing key from a literal"
fi
exit $fail
