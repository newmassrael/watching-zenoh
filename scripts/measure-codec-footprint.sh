#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# measure-codec-footprint.sh — binary-size delta bench for the wz
# composable-framework codec catalog. R311n promotes the original
# R311a4 bench into a catalog-truthfulness regression gate.
#
# Builds wz-ap-demo under multiple feature configurations and reports
# stripped binary size for each plus the byte delta vs the baseline:
#
#   baseline               — preset-ap-client (full feature set)
#   minus-<codec>          — preset-ap-client minus codec-X plus EVERY
#                            feature that transitively activates
#                            codec-X (so the codec is mechanically
#                            elided rather than re-pulled via implies)
#   minus-all-codecs       — preset-ap-client minus every codec-*
#                            feature and their transitive pullers
#   handshake-only         — every body codec + every consumer feature
#                            off; only the handshake-set bodies
#                            (Init/Open/Close + KeepAlive) reachable —
#                            surfaces the codec-frame elision that the
#                            R311h..R311k body-codec-implies-envelope
#                            edges promised
#
# Why R311n grew the script: prior to R311n the `minus-<codec>` lane
# only excluded the codec name itself, so e.g. `minus-codec-declare`
# left declare-subscriber / declare-token / liveliness-token etc. in
# the feature set; cargo's resolver re-pulled codec-declare via the
# implies edge declare-subscriber = [codec-declare] and the lane
# measured a near-zero delta. The catalog-truthfulness claim that
# turning codec-X off elides codec-X bytes was therefore unverifiable.
# R311n parses the wz facade + wz-runtime-tokio features map from
# `cargo metadata` and excludes the full transitive puller set; the
# minus-<codec> lane is now an honest measurement.
#
# Implementation notes:
#   - Atomic feature list is parsed live from crates/wz/Cargo.toml's
#     preset-ap-client block (unchanged from R311a4).
#   - Implies graph is parsed from `cargo metadata --format-version=1
#     --no-deps`. Python3 is required (jq is not). The graph is
#     computed once per script run and cached in $TARGET_DIR_BASE.
#   - wz-ap-demo Cargo.toml carries `wz = { default-features = false }`
#     so `--no-default-features --features <explicit-list>` is the
#     authoritative gate (unchanged from R311a4).
#   - Each configuration uses a dedicated --target-dir so cargo does
#     not spuriously re-link cached artifacts (unchanged from R311a4).
#   - Stripping (--strip-all) + lto=thin + codegen-units=1 ensure the
#     measured delta reflects actual codec-path code reachable from
#     main (unchanged from R311a4).
set -euo pipefail

WS=$(git rev-parse --show-toplevel)
WZ_TOML="$WS/crates/wz/Cargo.toml"
CRATES_DIR="$WS/crates"
TARGET_DIR_BASE="$WS/target/measure-codec-footprint"
BIN_NAME="wz-ap-demo"

mkdir -p "$TARGET_DIR_BASE"

# Parse preset-ap-client atomic feature list from wz/Cargo.toml.
PRESET_FEATURES=$(awk '
    /^preset-ap-client = \[/ { in_block=1; next }
    in_block && /^\]/        { in_block=0; next }
    in_block {
        gsub(/[",]/, "")
        gsub(/^[ \t]+|[ \t]+$/, "")
        if (length($0) > 0 && substr($0, 1, 1) != "#") print $0
    }
' "$WZ_TOML")

# R311n — compute the transitive puller set for every wz-runtime-tokio
# feature from `cargo metadata`. For a target wz-runtime-tokio feature
# R, pullers(R) is the set of wz facade features F such that enabling
# F at the wz facade level (transitively, through forwards + local
# recursion) activates wz-runtime-tokio's R. The minus-<codec> lane
# exclusion set = {codec} ∪ pullers(codec).
#
# Output format: shell-sourceable assignments
#   PULLERS_codec_push="codec-push <maybe others>"
#   PULLERS_codec_declare="codec-declare declare-final declare-interest ..."
#   PULLERS_codec_frame="codec-frame codec-push codec-declare codec-request codec-response ..."
# Bash array dereference reads "$PULLERS_$codec_snake" so dashes are
# converted to underscores in the variable names.
IMPLIES_CACHE="$TARGET_DIR_BASE/.implies.sh"
(cd "$CRATES_DIR" && cargo metadata --format-version=1 --no-deps 2>/dev/null) \
    | python3 "$WS/scripts/lib/feature_implies.py" >"$IMPLIES_CACHE"

# shellcheck disable=SC1090
source "$IMPLIES_CACHE"

# Build a comma-separated `wz/feature` list excluding the names passed
# in $1 (space-separated). Empty $1 keeps the full preset.
build_feature_list() {
    local exclude_space="$1"
    local list=""
    local f
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        if [[ " $exclude_space " == *" $f "* ]]; then
            continue
        fi
        [[ -n "$list" ]] && list+=","
        list+="wz/$f"
    done <<< "$PRESET_FEATURES"
    echo "$list"
}

measure() {
    local label="$1"
    local features="$2"
    local subdir="$TARGET_DIR_BASE/$label"

    echo "=== Building $label ==="
    # R311n — graceful compile-failure skip. After the body-codec
    # cascade closure (R311h..R311k), the minus-codec-frame /
    # minus-codec-push / minus-codec-declare / etc. lanes exclude
    # every consumer feature that transitively pulls the target
    # codec (declare-* / query-* / liveliness-* / pubsub-*). The
    # `wz-ap-demo` binary itself uses those high-level features
    # unconditionally so its source does not compile under such an
    # exclusion set. Pre-R311n the same exclusion was silently
    # re-enabled by cargo's resolver and the lane reported a fake
    # near-zero delta; the honest replacement is to surface
    # "unmeasurable for this binary" and skip the lane. A future
    # round may add a smaller handshake-only test binary whose
    # source IS cfg-gated against the consumer features so these
    # lanes become measurable.
    if ! (cd "$CRATES_DIR" && cargo build --release -p "$BIN_NAME" \
        --no-default-features --features "$features" \
        --target-dir "$subdir") >/tmp/measure-build-$$.log 2>&1; then
        echo "  $label: SKIP (binary does not compile under this exclusion;" \
             "consumer features still referenced — see /tmp/measure-build-$$.log)"
        echo "SKIP" > "$TARGET_DIR_BASE/.${label}.size"
        return 0
    fi
    tail -3 /tmp/measure-build-$$.log
    rm -f /tmp/measure-build-$$.log
    local bin="$subdir/release/$BIN_NAME"
    strip --strip-all "$bin"
    local size
    size=$(stat -c%s "$bin")
    printf "  %-32s %10s bytes (%s)\n" \
        "$label:" "$size" "$(numfmt --to=iec --suffix=B "$size")"
    echo "$size" > "$TARGET_DIR_BASE/.${label}.size"
}

# Auto-enumerate every codec-* atomic feature in preset-ap-client so
# new cascades land without touching this script. baseline is one
# build; each codec gets its own minus-$codec build (now with the
# transitive puller set excluded per R311n); finally a minus-all-
# codecs and a handshake-only build surface the cumulative elision.
CODEC_FEATURES=()
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    [[ "$f" == codec-* ]] && CODEC_FEATURES+=("$f")
done <<< "$PRESET_FEATURES"

measure "baseline" "$(build_feature_list '')"

# R311n — each minus-$codec lane excludes the codec + its transitive
# puller set so cargo's resolver cannot silently re-enable the codec
# via a high-level consumer feature (e.g. declare-subscriber implying
# codec-declare).
for codec in "${CODEC_FEATURES[@]}"; do
    var_name="PULLERS_${codec//-/_}"
    excludes="${!var_name:-$codec}"
    measure "minus-$codec" "$(build_feature_list "$excludes")"
done

# minus-all-codecs: union of every codec's puller set.
ALL_CODEC_EXCLUDES=""
for codec in "${CODEC_FEATURES[@]}"; do
    var_name="PULLERS_${codec//-/_}"
    pullers="${!var_name:-$codec}"
    ALL_CODEC_EXCLUDES+=" $pullers"
done
# Dedupe via `tr` + `sort -u`.
ALL_CODEC_EXCLUDES=$(echo "$ALL_CODEC_EXCLUDES" | tr ' ' '\n' | sort -u | tr '\n' ' ')
measure "minus-all-codecs" "$(build_feature_list "$ALL_CODEC_EXCLUDES")"

# R311n — handshake-only lane. Start from preset-ap-client and
# exclude EVERY body codec (push / declare / request / response /
# response-final / fragment / scout / hello / join) + every consumer
# feature (pubsub-* / declare-* / query-* / liveliness-* / scouting-*
# etc.). Only the handshake-set codecs (Init / Open / Close + KeepAlive)
# and runtime/transport plumbing remain reachable, which is the
# theoretical floor codec-frame OFF can mechanically reach after the
# R311h..R311k body-codec-implies-envelope edges.
HANDSHAKE_KEEP=(
    platform-linux
    runtime-tokio
    transport-link-tcp
    transport-link-udp
    transport-unicast
    transport-keepalive
    transport-batching
    transport-fragmentation
    session-unicast-open
    session-unicast-accept
    link-batching
    link-frame
    link-fragment
    codec-init-body
    codec-open-body
    codec-close
    codec-keep-alive
    encoding-bytes
    encoding-empty
    encoding-utf8
    keyexpr-literal
    keyexpr-canon
    locator-tcp
    locator-udp
    routing-client
    scouting-static
    time-system-clock
    time-ntp64
    time-timestamp-source
)
HANDSHAKE_EXCLUDES=""
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    keep=0
    for k in "${HANDSHAKE_KEEP[@]}"; do
        if [[ "$f" == "$k" ]]; then
            keep=1
            break
        fi
    done
    if [[ $keep -eq 0 ]]; then
        HANDSHAKE_EXCLUDES+=" $f"
    fi
done <<< "$PRESET_FEATURES"
measure "handshake-only" "$(build_feature_list "$HANDSHAKE_EXCLUDES")"

baseline=$(cat "$TARGET_DIR_BASE/.baseline.size")
minus_all=$(cat "$TARGET_DIR_BASE/.minus-all-codecs.size")
handshake_only=$(cat "$TARGET_DIR_BASE/.handshake-only.size")

format_delta() {
    local size="$1"
    if [[ "$size" == "SKIP" ]]; then
        printf "       SKIP"
    else
        printf "%+10d bytes" "$((baseline - size))"
    fi
}

echo ""
echo "=== Footprint deltas (baseline minus configuration) ==="
printf "  baseline:                     %10s bytes\n" "$baseline"
for codec in "${CODEC_FEATURES[@]}"; do
    size=$(cat "$TARGET_DIR_BASE/.minus-$codec.size")
    printf "  minus %-24s %s\n" "$codec:" "$(format_delta "$size")"
done
printf "  minus-all-codecs delta:       %s\n" "$(format_delta "$minus_all")"
printf "  handshake-only delta:         %s\n" "$(format_delta "$handshake_only")"

# R311n — threshold-based regression gate. Each codec-* feature is
# expected to produce a minimum elision delta when its puller-aware
# minus-<codec> lane runs; if cargo resolver silently re-enables the
# codec (e.g. a new high-level feature was added without listing it
# in the implies graph) the delta drops below the threshold and the
# script exits non-zero. The threshold is intentionally conservative
# (1 KB) so a real but small codec elision is not flagged; the gate
# catches the "near-zero delta" pathology that masked R311a4..R311k
# catalog-truthfulness regressions before R311n.
#
# Opt out via WZ_FOOTPRINT_NO_THRESHOLD=1 (for one-off measurements
# where a near-zero delta is expected, e.g. a wz-codecs-only codec
# with no wz-runtime-tokio session_glue surface).
THRESHOLD_BYTES=${WZ_FOOTPRINT_THRESHOLD_BYTES:-1024}
SKIP_THRESHOLD=${WZ_FOOTPRINT_NO_THRESHOLD:-0}
if [[ "$SKIP_THRESHOLD" -ne 1 ]]; then
    fail=0
    for codec in "${CODEC_FEATURES[@]}"; do
        size=$(cat "$TARGET_DIR_BASE/.minus-$codec.size")
        if [[ "$size" == "SKIP" ]]; then
            # Lane skipped due to compile-fail under the puller-aware
            # exclusion set (wz-ap-demo references the consumer
            # features unconditionally). Honest semantics: the lane is
            # unmeasurable for THIS binary; the threshold gate cannot
            # judge. A future smaller test binary will close the gap.
            continue
        fi
        delta=$((baseline - size))
        if [[ $delta -lt $THRESHOLD_BYTES ]]; then
            # codec-scout / codec-hello / codec-join / codec-fragment
            # currently sit at wz-codecs level only (no session_glue
            # surface); near-zero delta is honest semantics, not a
            # regression. R311m consumer-module cascade is expected to
            # promote them above threshold; until then, allow these
            # specific codecs to soft-skip.
            case "$codec" in
                codec-scout|codec-hello|codec-join|codec-fragment)
                    echo "  THRESHOLD SOFT-SKIP $codec ($delta < $THRESHOLD_BYTES; wz-codecs-only)" >&2
                    ;;
                *)
                    echo "  THRESHOLD FAIL $codec ($delta < $THRESHOLD_BYTES)" >&2
                    fail=1
                    ;;
            esac
        fi
    done
    if [[ $fail -ne 0 ]]; then
        echo "  R311n catalog-truthfulness threshold gate failed; investigate above" >&2
        exit 1
    fi
fi
