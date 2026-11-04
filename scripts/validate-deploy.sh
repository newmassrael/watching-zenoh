#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# validate-deploy.sh — schema sanity check on deploy/*.yaml files.
#
# Phase Y (R50) placeholder: the full `sce-codegen build
# deploy/<x>.yaml` end-to-end exercise requires SCE upstream to
# implement the `build` subcommand (currently sce-codegen exposes
# `generate`, `orchestrate`, `manifest`, `verify`, etc. — no `build`).
# Until that lands, this script does what we CAN validate today:
#
#   1. YAML parses as well-formed (no syntax errors).
#   2. The document is one of the two kinds deploy/ holds, named by its
#      top-level key:
#      - `machines`: a deployment of nodes. Each machine block declares
#        the schema fields needed by the future `build` subcommand
#        (platform/class/os, pool_defaults, qos, security, scouting,
#        links).
#      - `codecs`: a codec deployment, the capacity a storage profile
#        holds of each field the protocol bounds by nothing (SCE Forge,
#        the `codecs:` block of a deployment; ADR 0077 section 7). Only
#        its shape is checked here: each entry a `capacity` mapping of
#        field names to positive integers. Whether each codec and field
#        exists is the generator's judgement, which `verify-codegen.sh`
#        asks with `--deploy`; this script does not keep a second list.
#      A document with both keys, or neither, is refused.
#
# This is a holding-pattern gate. Once SCE ships `build`, this
# script either upgrades to invoke that subcommand or is retired in
# favor of CI-side `sce-codegen build` invocation.
#
# Exit codes:
#   0  all deploy/*.yaml files pass the lightweight schema check.
#   1  any file fails YAML parse or schema check.
#   2  required tooling missing (python3-yaml).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT/deploy"

if ! command -v python3 >/dev/null 2>&1; then
    echo "validate-deploy: python3 not on PATH" >&2
    exit 2
fi

if ! python3 -c "import yaml" 2>/dev/null; then
    echo "validate-deploy: python3 yaml module unavailable" >&2
    echo "  install: sudo apt-get install -y python3-yaml" >&2
    exit 2
fi

fail=0
for yaml_file in "$DEPLOY_DIR"/*.yaml; do
    name="$(basename "$yaml_file")"
    if python3 - "$yaml_file" "$ROOT" <<'PYTHON'
import sys
from pathlib import Path

import yaml

path = sys.argv[1]
# Open-debt item 900 — a machine's `zid` and `sessions:` list are judged by
# the one module that documents them; a refusal names the key it refuses.
sys.path.insert(0, str(Path(sys.argv[2]) / "scripts" / "lib"))
import deploy_sessions  # noqa: E402
with open(path, "r", encoding="utf-8") as f:
    try:
        doc = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"  YAML parse error: {e}")
        sys.exit(1)

if not isinstance(doc, dict):
    print("  expected top-level mapping")
    sys.exit(1)
kinds = [key for key in ("machines", "codecs") if key in doc]
if len(kinds) != 1:
    print(
        "  a deployment names exactly one kind by its top-level key, "
        f"`machines` or `codecs`; this one names {kinds or 'neither'}"
    )
    sys.exit(1)

if kinds == ["codecs"]:
    codecs = doc["codecs"]
    if not isinstance(codecs, dict) or not codecs:
        print("  codecs must be a non-empty mapping")
        sys.exit(1)
    for codec_name, codec in codecs.items():
        if not isinstance(codec, dict) or set(codec) != {"capacity"}:
            print(f"  codec {codec_name!r}: expected a mapping holding only `capacity`")
            sys.exit(1)
        capacity = codec["capacity"]
        if not isinstance(capacity, dict) or not capacity:
            print(f"  codec {codec_name!r}: capacity must be a non-empty mapping")
            sys.exit(1)
        for field, held in capacity.items():
            # bool is an int in Python; a capacity of `true` is not a count.
            if isinstance(held, bool) or not isinstance(held, int) or held < 1:
                print(
                    f"  codec {codec_name!r}: capacity of {field!r} must be a "
                    f"positive integer, not {held!r}"
                )
                sys.exit(1)
    print("  OK")
    sys.exit(0)

if not isinstance(doc["machines"], dict) or not doc["machines"]:
    print("  machines must be a non-empty mapping")
    sys.exit(1)

for machine_name, machine in doc["machines"].items():
    if not isinstance(machine, dict):
        print(f"  machine {machine_name!r} must be a mapping")
        sys.exit(1)
    # platform block is the minimum required field per
    # RFC §5.K — class + os are the deploy-driver dispatch keys.
    if "platform" not in machine:
        print(f"  machine {machine_name!r}: missing platform block")
        sys.exit(1)
    plat = machine["platform"]
    if not isinstance(plat, dict):
        print(f"  machine {machine_name!r}: platform must be a mapping")
        sys.exit(1)
    for required in ("class", "os"):
        if required not in plat:
            print(
                f"  machine {machine_name!r}: platform.{required} missing"
            )
            sys.exit(1)
    refusals = deploy_sessions.validate_machine(machine_name, machine, Path(sys.argv[2]))
    if refusals:
        for refusal in refusals:
            print(f"  {refusal}")
        sys.exit(1)
print("  OK")
sys.exit(0)
PYTHON
    then
        printf "validate-deploy: %-30s OK\n" "$name"
    else
        printf "validate-deploy: %-30s FAIL\n" "$name"
        fail=1
    fi
done

if [[ $fail -eq 0 ]]; then
    echo "validate-deploy: all deploy/*.yaml passed lightweight schema check"
    echo "  NOTE: full sce-codegen build pipeline pending SCE upstream"
    echo "        'build' subcommand implementation (R50 carry)."
fi
exit $fail
