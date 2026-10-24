#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R3491 (no register item) -- the session lifecycle verbs do not compile without a
# secure channel. The work item is open-debt 923, which is not a store `debt-` id.
#
# ## What it holds
#
# Decision D2 of docs/session-lifecycle-intent.md: a lifecycle verb is accepted
# only from a peer whose key a secure channel proved (D1, D9), so a build with no
# such channel must not compile the verbs at all. `wz-session-core` refuses
# `session-close-ingress` without `secure-channel` by a `compile_error!`, and the
# link features that provide a channel (`transport-link-tls`,
# `transport-link-quic` in `wz-runtime-tokio`) turn `secure-channel` on.
#
# A guard is a claim about a build that is NOT made, and nothing else in the tree
# builds one: every lane that turns the verbs on names a channel, so a guard that
# stopped refusing would stay green everywhere. This gate builds the refused
# combinations and requires the refusal, by its own sentence, beside the admitted
# combination as the control that the build itself is sound:
#
#   wz-session-core   session-close-ingress                  -> refused
#   wz-session-core   session-close-ingress,secure-channel   -> builds
#   wz-runtime-tokio  session-close-ingress                  -> refused (the
#                     runtime's forward must not bring a channel with it)
#
# Usage:
#   lifecycle-channel-guard-gate.sh
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../crates" || exit 2

# The guard's own words, backticks included: escaped, so the text is data and never a command.
GUARD="needs \`secure-channel\`"
fail=0
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

refused() {
    local pkg="$1" feats="$2" log="$work/$1.$2.log"
    if cargo check -p "$pkg" --features "$feats" --quiet >"$log" 2>&1; then
        echo "lifecycle-channel-guard: FAIL -- $pkg --features $feats BUILT; the lifecycle verbs compiled with no secure channel (decision D2)" >&2
        fail=1
    elif ! grep -qF "$GUARD" "$log"; then
        echo "lifecycle-channel-guard: FAIL -- $pkg --features $feats failed, but not by the D2 guard; its last lines:" >&2
        tail -n 15 "$log" >&2
        fail=1
    else
        echo "  lifecycle-channel-guard: $pkg --features $feats refused by the D2 guard"
    fi
}

admitted() {
    local pkg="$1" feats="$2" log="$work/$1.$2.log"
    if cargo check -p "$pkg" --features "$feats" --quiet >"$log" 2>&1; then
        echo "  lifecycle-channel-guard: $pkg --features $feats builds"
    else
        echo "lifecycle-channel-guard: FAIL -- $pkg --features $feats did not build, so the refusals above prove nothing; its last lines:" >&2
        tail -n 15 "$log" >&2
        fail=1
    fi
}

refused wz-session-core session-close-ingress
admitted wz-session-core session-close-ingress,secure-channel
refused wz-runtime-tokio session-close-ingress

if [[ $fail -ne 0 ]]; then
    exit 1
fi
echo "  lifecycle-channel-guard: the verbs are refused without a secure channel and built with one"
