#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
#   2. Required top-level keys are present (`machines`).
#   3. Each machine block declares the schema fields needed by the
#      future `build` subcommand (platform/class/os, pool_defaults,
#      qos, security, scouting, links).
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
    if python3 - "$yaml_file" <<'PYTHON'
import sys
import yaml

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    try:
        doc = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"  YAML parse error: {e}")
        sys.exit(1)

if not isinstance(doc, dict):
    print("  expected top-level mapping")
    sys.exit(1)
if "machines" not in doc:
    print("  missing required key: machines")
    sys.exit(1)
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
