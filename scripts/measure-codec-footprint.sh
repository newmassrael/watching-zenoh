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
        # R311y435 — SEPARATE THE TWO FAILURE MODES. Until this round both landed
        # as one SKIP, and a SKIP is green, so a genuine catalog defect was
        # indistinguishable from an honest measurement limit for as long as the
        # lane existed:
        #
        #   * the measurement BINARY does not compile — `wz-ap-demo` references
        #     consumer features unconditionally, so an exclusion set that removes
        #     them takes its source with it. Nothing is wrong with the catalog;
        #     this binary just cannot express the profile. Honest SKIP.
        #   * a LIBRARY crate does not compile — the profile itself is broken:
        #     some feature is used without being selected. That IS the
        #     catalog-truthfulness defect this gate exists to catch, and swallowing
        #     it as a SKIP is the gate reporting green on its own subject matter.
        #
        # Both R311y435 fixes were the second kind and had been hiding here:
        # `pubsub-put` used `wz_codecs::push` without selecting `codec-push`, and
        # `prune_declaration` outlived its callers into a `never used` build
        # failure. The minus-codec-push lane went from SKIP to a measured
        # 10072-byte delta once the first was written down.
        local culprit
        # The backticks below are literal cargo output being matched, not command
        # substitution, so the pattern stays single-quoted.
        # shellcheck disable=SC2016
        culprit=$(grep -oE 'could not compile `[^`]+`' /tmp/measure-build-$$.log \
            | head -1 | sed -e 's/could not compile `//' -e 's/`$//')
        if [[ -n "$culprit" && "$culprit" != "$BIN_NAME" ]]; then
            echo "  $label: CATALOG DEFECT — library crate \`$culprit\` does not" \
                 "compile under this exclusion. A feature is USED without being" \
                 "SELECTED; declare the edge in that crate's Cargo.toml (or gate" \
                 "the code to match its callers). See /tmp/measure-build-$$.log" >&2
            echo "DEFECT" > "$TARGET_DIR_BASE/.${label}.size"
            return 0
        fi
        echo "  $label: SKIP ($BIN_NAME does not compile under this exclusion;" \
             "consumer features still referenced — see /tmp/measure-build-$$.log)"
        echo "SKIP" > "$TARGET_DIR_BASE/.${label}.size"
        return 0
    fi
    tail -3 /tmp/measure-build-$$.log
    rm -f /tmp/measure-build-$$.log
    local bin="$subdir/release/$BIN_NAME"
    # R311y822 — capture the DEFINED-SYMBOL SET, and strip a COPY rather than
    # the linked artifact. Both halves were found by running this:
    #
    #   * the release profile sets no `strip`, so the linked binary already
    #     carries a symbol table. Reading it costs nothing; re-linking an
    #     unstripped build would have cost a whole second pass per lane.
    #   * `strip --strip-all "$bin"` used to edit cargo's OWN output. cargo
    #     hardlinks `release/$BIN_NAME` to `release/deps/<bin>-<hash>`, so the
    #     strip poisoned the cached artifact, and a re-run that skipped the
    #     relink then had NO symbols left to read. Measured: after one shard
    #     run, `.baseline.syms` and `.minus-codec-close.syms` came back with 0
    #     lines while every freshly-relinked lane had ~6300. A witness gate
    #     reading that empty set would have judged "the symbol is absent" and
    #     reported green, which is the R311y435 absence-reads-as-success shape.
    #     Stripping a copy leaves the artifact cargo linked untouched.
    #
    # Demangled (`-C`) so the witness map below can be written in the Rust path
    # a reader can find with grep, rather than in a v0 mangling that changes
    # with the crate disambiguator.
    local stripped="$subdir/release/$BIN_NAME.stripped"
    nm -C --defined-only "$bin" > "$TARGET_DIR_BASE/.${label}.syms" 2>/dev/null || :
    cp -f "$bin" "$stripped"
    strip --strip-all "$stripped"
    local size
    size=$(stat -c%s "$stripped")
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

# R311y388 — optional shard filter for parallel Layer F.
# WZ_FOOTPRINT_SHARDS=n + WZ_FOOTPRINT_SHARD=i (0-based) restrict THIS run to
# the codec lanes whose index % n == i (round-robin). Shards 0..n-1 PARTITION
# the full codec set with no gap and no overlap, so a CI matrix over [0..n-1]
# measures every codec exactly once (drop-proof: the modulo partition is a
# property of the codec SET parsed above, independent of the matrix — the only
# way to miss a codec is to run fewer than n shards, a static ci.yml invariant
# co-located with WZ_FOOTPRINT_SHARDS). The baseline is (re)built on every
# shard because every codec delta is computed against it. minus-all-codecs +
# handshake-only are whole-catalog lanes (they exclude the FULL codec set, not a
# per-codec one) and run ONLY on shard 0. Unset / SHARDS<=1 => run every lane
# (unchanged local + default behavior).
FULL_CODEC_FEATURES=("${CODEC_FEATURES[@]}")
FOOTPRINT_SHARDS="${WZ_FOOTPRINT_SHARDS:-1}"
FOOTPRINT_SHARD="${WZ_FOOTPRINT_SHARD:-0}"
if [[ "$FOOTPRINT_SHARDS" -gt 1 ]]; then
    if [[ "$FOOTPRINT_SHARD" -lt 0 || "$FOOTPRINT_SHARD" -ge "$FOOTPRINT_SHARDS" ]]; then
        echo "measure-codec-footprint: WZ_FOOTPRINT_SHARD=$FOOTPRINT_SHARD out of range [0,$FOOTPRINT_SHARDS)" >&2
        exit 2
    fi
    sharded=()
    for i in "${!FULL_CODEC_FEATURES[@]}"; do
        if [[ $(( i % FOOTPRINT_SHARDS )) -eq "$FOOTPRINT_SHARD" ]]; then
            sharded+=("${FULL_CODEC_FEATURES[$i]}")
        fi
    done
    CODEC_FEATURES=("${sharded[@]}")
    echo "=== Layer F shard $FOOTPRINT_SHARD/$FOOTPRINT_SHARDS:" \
         "${#CODEC_FEATURES[@]} of ${#FULL_CODEC_FEATURES[@]} codec lanes" \
         "[${CODEC_FEATURES[*]}]" \
         "$([[ $FOOTPRINT_SHARD -eq 0 ]] && echo '+ minus-all + handshake')" "==="
fi

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

# minus-all-codecs: union of EVERY codec's puller set (the FULL catalog, not
# the shard subset). R311y388: a whole-catalog lane, so it runs only on shard 0.
ALL_CODEC_EXCLUDES=""
for codec in "${FULL_CODEC_FEATURES[@]}"; do
    var_name="PULLERS_${codec//-/_}"
    pullers="${!var_name:-$codec}"
    ALL_CODEC_EXCLUDES+=" $pullers"
done
# Dedupe via `tr` + `sort -u`.
ALL_CODEC_EXCLUDES=$(echo "$ALL_CODEC_EXCLUDES" | tr ' ' '\n' | sort -u | tr '\n' ' ')
if [[ "$FOOTPRINT_SHARD" -eq 0 ]]; then
    measure "minus-all-codecs" "$(build_feature_list "$ALL_CODEC_EXCLUDES")"
fi

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
if [[ "$FOOTPRINT_SHARD" -eq 0 ]]; then
    measure "handshake-only" "$(build_feature_list "$HANDSHAKE_EXCLUDES")"
fi

baseline=$(cat "$TARGET_DIR_BASE/.baseline.size")

format_delta() {
    local size="$1"
    if [[ "$size" == "SKIP" ]]; then
        printf "       SKIP"
    else
        printf "%+10d bytes" "$((baseline - size))"
    fi
}

echo ""
echo "=== Footprint deltas (baseline minus configuration) — shard $FOOTPRINT_SHARD/$FOOTPRINT_SHARDS ==="
printf "  baseline:                     %10s bytes\n" "$baseline"
for codec in "${CODEC_FEATURES[@]}"; do
    size=$(cat "$TARGET_DIR_BASE/.minus-$codec.size")
    printf "  minus %-24s %s\n" "$codec:" "$(format_delta "$size")"
done
if [[ "$FOOTPRINT_SHARD" -eq 0 ]]; then
    minus_all=$(cat "$TARGET_DIR_BASE/.minus-all-codecs.size")
    handshake_only=$(cat "$TARGET_DIR_BASE/.handshake-only.size")
    printf "  minus-all-codecs delta:       %s\n" "$(format_delta "$minus_all")"
    printf "  handshake-only delta:         %s\n" "$(format_delta "$handshake_only")"
fi

# R311n — elision regression gate: each codec-* feature must remove a minimum
# amount of code when its puller-aware minus-<codec> lane runs, or the catalog
# is claiming an optionality the build does not have.
#
# R311y436 — the ONE GLOBAL THRESHOLD (1024B) IS GONE, replaced by a pinned
# floor PER CODEC. The global number could not be right for thirteen codecs
# whose real deltas span 0 to 74KB, and it failed in both directions at once:
#
#   * TOO LOW to catch a regression in a large codec. codec-response elides
#     74472B; it could lose 98% of that and still clear 1024.
#   * TOO HIGH for small ones, which forced a hand-maintained SOFT-SKIP list
#     (codec-scout / codec-hello / codec-join / codec-fragment /
#     codec-keep-alive). Five of thirteen lanes were exempt, judging nothing,
#     and the list only ever grew. R311y435 established where that ends: a gate
#     whose exemptions absorb its own subject matter reports green forever.
#
# A per-codec floor fixes both. Every lane is judged, the exemption list is
# deleted outright, and a near-zero codec is pinned AT near-zero -- which is
# strictly more informative than exempting it, because a jump upward is then
# visible too. The floors below are MEASURED (R311y436, at 49f2ea9), each
# carried with a margin well above the LTO/inline noise floor observed across
# runs (+-32B: keep-alive read 208 and 224, scout/hello -144 and -128).
#
# WHEN A FLOOR MUST MOVE: re-pin it in the same commit as the change that moved
# it, with the before/after numbers in the ledger entry. A floor lowered on its
# own is the gate being silenced, exactly as MNEMOSYNE_MAX_SCHEMA raised alone
# would be (scripts/lib/schema-pin-gate.sh). Legitimate causes exist -- a
# refactor that consolidates paths reduces what any one codec can still remove
# -- and they are recorded, not waved through.
#
# R311y437 IS THE FIRST DELIBERATE RE-PIN, and it is what the paragraph above
# describes rather than an exception to it. Consolidating the eight
# per-capability `*_with_{lowlatency,qos,compression,shm}` open wrappers into one
# `*_with_offer` entrypoint dropped codec-close's elision 1944B -> 600B. That is
# the legitimate cause, not a re-pull: 600B is still real elision, an order of
# magnitude above the near-zero band, and it was BISECTED -- routing the demo
# back to the bare entrypoint restores 1944B exactly, so the delta is
# attributable to the consolidation and to nothing else. The gate caught it
# (`FLOOR FAIL codec-close (600B < pinned 1500B)`) before the refactor could
# land, which is the whole design.
#
# Opt out via WZ_FOOTPRINT_NO_THRESHOLD=1 (one-off measurements only).
declare -A CODEC_DELTA_FLOOR=(
    [codec-frame]=0            # lane SKIPs on this binary; floor unused until it is measurable
    [codec-fragment]=-256      # measured 0: no session_glue surface, wz-codecs level only
    # R311y580 — RE-PINNED 128 -> 64 (measured 208 -> 96), and this is the
    # deliberate re-pin the block above prescribes, not a silenced gate. NOT a
    # re-pull: with the feature off, `parse_inbound`'s KeepAlive arm (-96) and
    # `InboundFrame`'s drop glue for the variant (-77) both still disappear.
    # Per-symbol diff of the two UNSTRIPPED builds (`-C strip=none`, crate
    # disambiguators normalised out) is exactly three rows:
    #     +96  wz_session_core::inbound::parse_inbound
    #     +77  core::ptr::drop_glue::<wz_session_core::inbound::InboundFrame>
    #     -39  wz_runtime_tokio::session_glue::poll_and_dispatch_one::{closure#0}
    # The third row is the cause: R311y578 grew `parse_inbound` itself (the
    # `extfragment::project_markers` projection on the Fragment arm, +94 B on
    # the MCU axis too), which moved the inline boundary so the CALLER now
    # absorbs work the arm used to own. That is the "a refactor consolidated
    # the paths it used to own" case named above, measured rather than assumed.
    # A bodyless message's arm being 96 B is still real elision.
    # R311y878 — RE-PINNED 64 -> -1024, the THIRD deliberate re-pin the block
    # above prescribes and the second whose cause is the MEASUREMENT rather
    # than the code. It arrives with a witness in the same commit, which is
    # what that block requires and what makes it a re-pin instead of a
    # silencing: `CODEC_ELISION_WITNESS[codec-keep-alive]` below.
    #
    # Four builds of the same tree, one host, one toolchain, differing only in
    # how `parse_inbound_consuming` is shaped around an UNRELATED arm:
    #
    #   | transport-OAM arm                       | minus codec-keep-alive |
    #   |-----------------------------------------|------------------------|
    #   | absent (`T_MID_OAM if false`)           |                +240 B  |
    #   | present, inline in the match            |                -192 B  |
    #   | present, behind `#[inline(never)]`      |                 -96 B  |
    #   | present + keep-alive's own arm extracted|                 +64 B  |
    #
    # A 432 B spread on a lane whose pin was 64 B, driven by a message this
    # codec has nothing to do with. What the number tracks at that magnitude is
    # the CALLER's inline boundary, not the codec — the same finding the
    # [codec-close] re-pin above records, reached here by a different road.
    # Old: 64 (R311y580, was 208 -> 128; measured 96 then).
    [codec-keep-alive]=-1024
    [codec-init-body]=12000    # measured 14608
    [codec-open-body]=8000     # measured 10192
    # R311y822 — RE-PINNED 500 -> -1024, and the catalog-truthfulness claim for
    # this codec MOVES to CODEC_ELISION_WITNESS below rather than being dropped.
    # This is the second deliberate re-pin the block above prescribes, and it is
    # the first one whose cause is the MEASUREMENT rather than the code.
    #
    # R311y820 red this lane at -40B hosted / -72B local, one round after it
    # read +1792B. The per-symbol diff of the two unstripped builds says the
    # codec is elided exactly as the catalog promises:
    #
    #       -86  wz_session_core::handshake_encode::encode_close  (86 -> 0)
    #      -746  SessionFsmUnicastPolicy<SessionActionsBinding<..>>
    #      -153  wz_session_core::inbound::parse_inbound_consuming
    #       -77  core::ptr::drop_glue::<wz_session_core::inbound::InboundFrame>
    #       -73  core::ptr::drop_glue::<wz_ap_demo::teardown::TokenDropped>
    #       -72  <wz_session_core::inbound::InboundFrame>::ext_admission
    #     +1547  wz_ap_demo::runner::run_demo::{closure#0}
    #
    # The last row is the whole story, and it is not a re-pull. `run_demo`'s
    # async body is ONE 70KB symbol; R311y820 grew it (demo_session_init_params
    # became fallible, so five call sites gained an error branch), which moved
    # the inline boundary. In the minus-codec-close build the optimizer now
    # pulls ~1.5KB of formerly out-of-line code INTO that closure and swamps
    # the ~1.2KB the codec really removes. A whole-binary delta is a difference
    # of two 2.7MB binaries whose INLINING differs, and on this axis that
    # difference is an order of magnitude larger than the thing being measured.
    #
    # -1024 is chosen to sit below the observed swing rather than just below
    # today's reading, because a floor re-pinned to -128 would red again the
    # next time an unrelated edit moves that closure — and this lane is no
    # longer where the codec's truthfulness is judged.
    [codec-close]=-1024        # measured -72 (R311y822, was 600 -> floor 500)
    [codec-push]=8000          # measured 10072 (R311y435 revived this lane from SKIP)
    [codec-declare]=0          # lane SKIPs on this binary; floor unused until it is measurable
    [codec-request]=55000      # measured 66456
    [codec-response]=60000     # measured 74472
    [codec-response-final]=8000 # measured 9712
    [codec-scout]=-256         # measured -144: wz-codecs level only; negative is inline noise
    [codec-hello]=-256         # measured -144: same
)

# R311y822 — the ELISION WITNESS. A byte delta is a PROXY for the claim the
# catalog actually makes ("turning codec-X off removes codec-X's code"); this
# checks the claim itself, by name, and nothing the optimizer does to unrelated
# call sites can move it.
#
# Why it exists: see the [codec-close] re-pin above. When a codec's real
# contribution is smaller than the inline-boundary swing of the measurement
# binary, the proxy stops resolving it — and a floor loose enough not to red
# spuriously is a floor too loose to catch a re-pull. A codec in this position
# keeps a byte floor as a coarse backstop and gets its truthfulness judged HERE
# instead. This is the same move R311y436 made when it replaced one global
# threshold with per-codec floors: keep every lane judged, do not let a lane
# the number cannot serve fall back to "exempt".
#
# The witness is a symbol the codec OWNS — its encode entrypoint — which the
# demo reaches on the baseline profile. It FAILS CLOSED in both directions:
#
#   * absent from the BASELINE -> FAIL. Either the symbol was renamed (fix the
#     map) or the codec is no longer reachable from this binary at all, in
#     which case this lane judges nothing and must say so rather than pass.
#     This arm is also what makes an unreadable symbol table fatal: no `nm` on
#     PATH, or a stripped artifact, yields an empty set, and an empty set fails
#     the baseline check FIRST. A gate that cannot read its input must not
#     report green (the same rule Layer C0 applies to python3).
#   * still present in the MINUS build -> FAIL. That is the re-pull, which is
#     the defect this whole layer exists to catch.
#
# NOT a population allowlist: a codec with no entry here is judged by its floor
# exactly as before, so this can only ever add reject power. A codec whose
# floor is re-pinned INTO the noise band, though, must arrive with a witness in
# the same commit — that is what keeps the re-pin from being a silencing.
declare -A CODEC_ELISION_WITNESS=(
    [codec-close]="wz_session_core::handshake_encode::encode_close"
    # R311y878 — the second witness, and it had to be MADE rather than found.
    # A name-set diff of `.baseline.syms` against `.minus-codec-keep-alive.syms`
    # returned ZERO symbols present in one and absent from the other: a
    # bodyless message's arm inlines away completely, so this codec had no name
    # to pin and its byte lane was measuring the caller's inline boundary
    # instead (208 -> 128 -> 96 -> 64, one re-pin per round that grew
    # `parse_inbound_consuming`). `decode_keep_alive` is that arm behind an
    # `#[inline(never)]` boundary, so the claim the catalog makes is now
    # checkable by name here rather than only by a delta that cannot resolve it.
    [codec-keep-alive]="wz_session_core::inbound::decode_keep_alive"
)

SKIP_THRESHOLD=${WZ_FOOTPRINT_NO_THRESHOLD:-0}
if [[ "$SKIP_THRESHOLD" -ne 1 ]]; then
    fail=0
    for codec in "${CODEC_FEATURES[@]}"; do
        size=$(cat "$TARGET_DIR_BASE/.minus-$codec.size")
        if [[ "$size" == "DEFECT" ]]; then
            # R311y435 — a LIBRARY crate failed to compile under this exclusion:
            # a feature is used without being selected. This is the very defect
            # the gate exists to catch, so it FAILS rather than skipping. It is
            # not a threshold question (there is no binary to measure), which is
            # why it is judged here rather than by the delta comparison below.
            echo "  CATALOG DEFECT $codec (library does not compile; see above)" >&2
            fail=1
            continue
        fi
        if [[ "$size" == "SKIP" ]]; then
            # Lane skipped because the MEASUREMENT BINARY (wz-ap-demo) references
            # consumer features unconditionally, so this exclusion set removes its
            # source. Honest semantics: unmeasurable for THIS binary, and the
            # threshold gate cannot judge. Distinct from DEFECT above, which is a
            # broken profile rather than an unexpressible one. A future smaller
            # test binary — cfg-gated against the consumer features — closes the
            # remaining lanes (codec-frame / codec-declare / minus-all-codecs /
            # handshake-only as of R311y435).
            continue
        fi
        delta=$((baseline - size))
        floor="${CODEC_DELTA_FLOOR[$codec]-}"
        if [[ -z "$floor" ]]; then
            # An UNPINNED codec is a failure, not a pass. A new atomic codec
            # feature lands in preset-ap-client and is auto-enumerated into
            # CODEC_FEATURES, so without this it would be measured and then
            # silently ignored — the same "absence reads as success" shape that
            # let the R311y435 defects hide behind SKIP.
            echo "  FLOOR MISSING $codec (measured ${delta}B, no pinned floor)" >&2
            echo "    Add it to CODEC_DELTA_FLOOR above with the measured value" >&2
            echo "    minus a margin, and cite the measurement in the ledger." >&2
            fail=1
            continue
        fi
        if (( delta < floor )); then
            echo "  FLOOR FAIL $codec (${delta}B < pinned ${floor}B)" >&2
            echo "    This codec now elides LESS code than the pin records." >&2
            echo "    Either a consumer re-pulls it (the catalog-truthfulness" >&2
            echo "    defect this gate exists to catch), or a refactor" >&2
            echo "    consolidated the paths it used to own. The second is" >&2
            echo "    legitimate but MUST be re-pinned deliberately, with the" >&2
            echo "    before/after numbers in the ledger entry -- never by" >&2
            echo "    lowering this constant on its own." >&2
            fail=1
        fi
        # R311y822 — the by-name half. Runs for every codec that pins a witness,
        # INDEPENDENTLY of whether the byte floor above passed: the two answer
        # different questions and a codec can clear one while failing the other.
        witness="${CODEC_ELISION_WITNESS[$codec]-}"
        if [[ -n "$witness" ]]; then
            base_syms="$TARGET_DIR_BASE/.baseline.syms"
            minus_syms="$TARGET_DIR_BASE/.minus-$codec.syms"
            if ! grep -qF -- "$witness" "$base_syms" 2>/dev/null; then
                echo "  WITNESS MISSING $codec ($witness not in the baseline)" >&2
                echo "    The baseline binary does not define this codec's own" >&2
                echo "    symbol, so the minus lane cannot show it disappearing" >&2
                echo "    and this lane judges nothing. Either the symbol was" >&2
                echo "    renamed (fix CODEC_ELISION_WITNESS), the codec stopped" >&2
                echo "    being reachable from $BIN_NAME, or the symbol table" >&2
                echo "    could not be read at all -- no nm on PATH, or a tree" >&2
                echo "    whose lane dirs were stripped in place by the" >&2
                echo "    pre-R311y822 script, which cargo will not relink." >&2
                echo "    For the last one: rm -rf $TARGET_DIR_BASE" >&2
                fail=1
            elif grep -qF -- "$witness" "$minus_syms" 2>/dev/null; then
                echo "  WITNESS RE-PULL $codec ($witness survives the exclusion)" >&2
                echo "    A consumer still reaches this codec's code with the" >&2
                echo "    feature excluded -- the catalog-truthfulness defect," >&2
                echo "    measured by name rather than by byte delta. Declare" >&2
                echo "    the missing implies edge, or gate the code to match" >&2
                echo "    its callers; never drop the witness." >&2
                fail=1
            else
                printf "  witness OK %-24s %s elided\n" "$codec:" "$witness"
            fi
        fi
    done
    if [[ $fail -ne 0 ]]; then
        echo "  R311n catalog-truthfulness threshold gate failed; investigate above" >&2
        exit 1
    fi
fi
