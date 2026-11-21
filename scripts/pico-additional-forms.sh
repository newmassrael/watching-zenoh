#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Build the pico C ABI library in its two forms from one feature list, on Linux, for the
# differential test that holds them to one wire (docs/capi-pico-additional-library.md):
#
#   scripts/pico-additional-forms.sh [<wz-capi-pico features>]
#
# The features are those of the library beyond its default build (a comma list), the additional
# features among them; by default the ones the differential scenario runs
# (crates/wz-capi-pico/tests/c/additional_split_scenario.c). Under the artifact root
# (scripts/lib/artifact-root.sh), in crates/target/pico-forms:
#
#   single/libwz_capi_pico.so       the one library: the core and the doors
#   split/libwz_capi_pico.so        the core alone (`--cfg wz_additional_apart`)
#   split/libwz_capi_pico_ext.so    the doors as a library of their own, which needs the core
#   include/                        zenoh-pico's headers with the config.h of this feature list's
#                                   arm, and wz_ext.h: one set for both forms, which share the arm
#   features                        the feature list, one line
#
# The doors' library is built with the features of that list it declares (the doors and the arm of
# the C types they read), over its defaults, which are the arm of the core's default build. Each
# form's exports are read back before the script ends: the core alone exports none of the doors,
# and the doors' library exports them and nothing of the core's. Exit 0 when both forms were built
# and read back so; non-zero, with the reason, otherwise.

set -u

features="${1:-e2e-sender,e2e-receiver,replay-cache}"
# shellcheck source=scripts/lib/artifact-root.sh
source "$(dirname "$0")/lib/artifact-root.sh"
wz_artifact_root_init "$PWD" || exit 2
out="$WZ_ARTIFACTS/crates/target/pico-forms"
build="$out/build"
py="$(command -v python3 || command -v python || true)"
if [ -z "$py" ]; then
    echo "pico-additional-forms: no python to read cargo's reports" >&2
    exit 2
fi

fail() {
    echo "pico-additional-forms: $1" >&2
    exit 1
}

rm -rf "$out/single" "$out/split" "$out/include"
mkdir -p "$out/single" "$out/split" "$out/include" "$build"

# The headers zenoh-pico's own build installs, named by cargo's report of that build: the same
# text for every arm but config.h, which is rendered for this list below (as the Windows package
# takes them, scripts/lib/pico_windows_package.py).
report="$(mktemp)"
(cd crates && cargo build --message-format=json-render-diagnostics -p zenoh-pico-sys \
    --target-dir "$build") > "$report" || fail "the pico headers did not build"
inc="$("$py" - "$report" <<'PY'
import json, os, sys
found = set()
for line in open(sys.argv[1], encoding="utf-8"):
    if not line.startswith("{"):
        continue
    msg = json.loads(line)
    if msg.get("reason") == "build-script-executed" and "zenoh-pico-sys" in msg.get("package_id", ""):
        found.add(os.path.join(msg["out_dir"], "include"))
if len(found) != 1:
    sys.exit(f"cargo reported {len(found)} zenoh-pico-sys build(s), not one")
print(found.pop())
PY
)" || fail "the build named no single pico header arm"
rm -f "$report"

# The one library: the core and the doors.
core_features=()
if [ -n "$features" ]; then
    core_features=(--features "$features")
fi
(cd crates && cargo build -p wz-capi-pico ${core_features[@]+"${core_features[@]}"} --target-dir "$build") \
    || fail "the one library did not build"
cp "$build/debug/libwz_capi_pico.so" "$out/single/" || fail "the one library is not where cargo builds it"

# The core alone: the same crate and features, with the doors left to the other library. Built after
# the one library into the same directory, so it replaces that file, which was copied out above.
(cd crates && cargo rustc -p wz-capi-pico --lib ${core_features[@]+"${core_features[@]}"} \
    --target-dir "$build" -- --cfg wz_additional_apart) || fail "the core alone did not build"
cp "$build/debug/libwz_capi_pico.so" "$out/split/" || fail "the core alone is not where cargo builds it"

# The doors' library, linked to the core just built: the features of the list it declares.
ext_features="$( (cd crates && cargo metadata --format-version 1 --no-deps) | "$py" -c '
import json, sys
features = [f for f in sys.argv[1].split(",") if f]
meta = json.load(sys.stdin)
ext = next(p for p in meta["packages"] if p["name"] == "wz-capi-pico-ext")
declared = set(ext["features"]) - {"default"}
print(",".join(f for f in features if f in declared))
' "$features")" || fail "the doors' library's features could not be read"
ext_args=()
if [ -n "$ext_features" ]; then
    ext_args=(--features "$ext_features")
fi
(cd crates && WZ_CAPI_PICO_CORE_DIR="$build/debug" cargo build -p wz-capi-pico-ext \
    ${ext_args[@]+"${ext_args[@]}"} --target-dir "$build") || fail "the doors' library did not build"
cp "$build/debug/libwz_capi_pico_ext.so" "$out/split/" || fail "the doors' library is not where cargo builds it"

# One header set for both forms: the installed tree with the config.h of this list's arm.
cp -R "$inc"/. "$out/include"/ || fail "the pico headers could not be copied"
"$py" scripts/lib/wz_config.py --pico-config-h "$features" > "$out/include/zenoh-pico/config.h" \
    || fail "the header of the arm did not render"
cp crates/wz-capi-core/include/wz_ext.h "$out/include/" || fail "wz_ext.h could not be copied"
echo "$features" > "$out/features"

# Read each form's exports back: a door is in the one library and in the doors' library, never in
# the core alone, and the doors' library exports nothing of the core's.
exports() { nm -D --defined-only "$1" | awk '{print $NF}'; }
has() { exports "$1" | grep -qx "$2"; }
door=wz_ext_e2e_sender_new
has "$out/single/libwz_capi_pico.so" "$door" || fail "the one library does not export $door"
has "$out/split/libwz_capi_pico_ext.so" "$door" || fail "the doors' library does not export $door"
has "$out/split/libwz_capi_pico_ext.so" wz_ext_additional_interface \
    || fail "the doors' library does not export wz_ext_additional_interface"
if has "$out/split/libwz_capi_pico.so" "$door"; then
    fail "the core alone exports $door: the doors were not left out"
fi
has "$out/split/libwz_capi_pico.so" wz_ext_interface_major_1 \
    || fail "the core alone does not export the extension interface"
if has "$out/split/libwz_capi_pico_ext.so" z_open; then
    fail "the doors' library exports z_open: it carries the core"
fi
echo "pico-additional-forms: both forms of [$features] in $out"
