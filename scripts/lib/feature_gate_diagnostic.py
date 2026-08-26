#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2115 (no register item) — a consumer who reaches for a FEATURE-GATED path
must be told WHICH FEATURE, and the compiler is the one asked.

Closes item 239 of the unregistered register, which lives outside this
repository -- which is why the citation above reads "no register item", the
same way `cdylib_soname_gate.py` does for item 521.

## The item, and how its premise turned out

Item 239 said a new consumer of `wz-capture` gets `could not find 'fields_json'
in 'wz_capture'` -- the module is not missing, the feature is off -- and that
"nothing at that point tells them which feature". It also recorded why the
obvious remedy is wrong: `compile_error!` is not lazy, so an arm that carries
one breaks every default build.

MEASURED before writing any of this, on rustc 1.97, with a real consumer crate
outside the workspace naming `wz_capture::fields_json::fields_json`:

    error[E0433]: cannot find `fields_json` in `wz_capture`
    note: found an item that was configured out
      --> crates/wz-capture/src/lib.rs:99:9
       |   ------------------- the item is gated behind the `dissect` feature

The premise is REFUTED. The toolchain grew the diagnostic and the item's reason
outlived the thing it described -- open-debt item 47's class, arriving in a
register entry rather than in a comment. A `use` import (E0432) gets the same
note; both shapes were run.

## So why a gate rather than a note saying "the compiler handles it"

Because that sentence is exactly what would rot next. The property holds today
for a reason nothing in this tree holds down: rustc emits the note only when the
`#[cfg(feature = ...)]` sits ON the item it configured out. Move the gate into a
`cfg_if!`, behind a re-export, or one module further in, and the note goes with
it -- silently, because the consumer who would have noticed is not in this
repository. A toolchain that stops emitting it does the same.

So the compiler is made an ORACLE instead of a claim: this builds a real
consumer crate against a real feature-off `wz-capture` and reads what rustc
says. Three ways to fail, and the middle one is the point:

  * the build SUCCEEDS -- the path is reachable without the feature, so the
    probe has been measuring nothing. A dead probe and a negative result are
    the same exit code, which is what this workspace keeps paying for;
  * the build fails and the note does NOT name the feature -- the consumer is
    back to guessing, which is the item;
  * a declared feature has no probe and no reason -- silence.

## Where the population comes from

`cargo metadata`, not a grep over the source. The features a package declares
and the transitive closure of `default` are cargo's own answer; every feature
outside that closure has to be either PROBED or declared as gating no public
path. A feature added tomorrow fails this until somebody decides which it is.

## What it deliberately does NOT cover, said out loud

ONE package. The axis is scoped to `wz-capture`, which is the crate item 239 is
about, and the banner counts the workspace packages it does not reach so the
bound is a number rather than an impression. Widening it is a decision about
how much build time a static-ish lane may spend, not an oversight here.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "crates"
PACKAGE = "wz-capture"

# The crate's own library name, as a consumer spells it in a path.
CRATE_PATH = "wz_capture"

# feature -> the probes that prove a consumer is told about it.
#
# Each probe is a whole `src/lib.rs` for a throwaway consumer. TWO SHAPES on
# purpose: a path expression resolves through E0433 and an import through
# E0432, and they are separate code paths in rustc -- a note present on one and
# absent on the other is precisely the half-answer this axis exists to catch.
PROBES: dict[str, list[tuple[str, str]]] = {
    "dissect": [
        (
            "a path expression",
            f"pub fn reach(d: &{CRATE_PATH}::Dissection, b: &[u8]) -> String {{\n"
            f"    {CRATE_PATH}::fields_json::fields_json(d, b, None, None)\n"
            f"}}\n",
        ),
        (
            "an import",
            f"use {CRATE_PATH}::payload_decode::Declarations;\n"
            f"pub fn hold(_d: &Declarations<'_>) {{}}\n",
        ),
    ],
}

# Features that gate no public path, each with the reason. A reason is what the
# next reader needs: the alternative is an empty list, which reads the same as
# "nobody got round to it".
NO_PUBLIC_PATH: dict[str, str] = {}

# The rustc note this axis is about, as a template over the feature name.
#
# The WORDING is the toolchain's and this gate is deliberately pinned to it: a
# looser match ("configured out") would keep passing on the day rustc stops
# naming the feature, which is the whole property. If a rustc release rewords
# it, the fix is here and the round that makes it should say which release.
NOTE = "the item is gated behind the `{feature}` feature"


def metadata() -> dict:
    """Cargo's own answer about this workspace."""
    out = subprocess.run(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(WORKSPACE / "Cargo.toml"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        print(
            "feature-gate-diagnostic: FAIL -- cargo metadata did not run, so the "
            "feature population could not be derived. A population this gate "
            "could not read is not an empty one.",
            file=sys.stderr,
        )
        print(out.stderr[-2000:], file=sys.stderr)
        sys.exit(1)
    return json.loads(out.stdout)


def default_closure(features: dict[str, list[str]]) -> set[str]:
    """Every feature `default` turns on, transitively.

    `dep/feature` entries are another package's business and are skipped; what
    is wanted here is the set of THIS package's features a plain build has.
    """
    seen: set[str] = set()
    stack = list(features.get("default", []))
    while stack:
        name = stack.pop()
        if "/" in name or name in seen:
            continue
        if name not in features:
            continue
        seen.add(name)
        stack.extend(features[name])
    return seen


def build_probe(
    feature: str, label: str, body: str, enabled: list[str], target_dir: str
) -> tuple[int, str]:
    """Compile one throwaway consumer against a feature-OFF `wz-capture`.

    The feature set is DERIVED: everything `default` would have turned on,
    minus the one under test, with `default-features = false` so the subtraction
    actually happens. That works the same for a feature outside the default set
    and for one inside it, which is what keeps this from needing a per-feature
    recipe nobody would maintain.
    """
    tmp = tempfile.mkdtemp(prefix="wz-feature-probe-")
    try:
        crate = pathlib.Path(tmp)
        (crate / "src").mkdir()
        (crate / "src" / "lib.rs").write_text(body)
        wanted = ", ".join(f'"{f}"' for f in sorted(enabled))
        (crate / "Cargo.toml").write_text(
            "[package]\n"
            'name = "wz-feature-probe"\n'
            'version = "0.0.0"\n'
            'edition = "2021"\n'
            "publish = false\n\n"
            "[dependencies]\n"
            f'{PACKAGE} = {{ path = "{WORKSPACE / PACKAGE}", '
            f"default-features = false, features = [{wanted}] }}\n\n"
            "[workspace]\n"
        )
        env = dict(os.environ)
        # The workspace's own target directory, so the dependencies this probe
        # needs are the ones the lane just built. Measured: 33s cold, 1s warm.
        env["CARGO_TARGET_DIR"] = target_dir
        out = subprocess.run(
            ["cargo", "build", "--manifest-path", str(crate / "Cargo.toml")],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        return out.returncode, out.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    meta = metadata()
    packages = {p["name"]: p for p in meta.get("packages", [])}
    if not packages:
        print(
            "feature-gate-diagnostic: FAIL -- cargo reported no workspace "
            "package at all.",
            file=sys.stderr,
        )
        return 1
    if PACKAGE not in packages:
        print(
            f"feature-gate-diagnostic: FAIL -- `{PACKAGE}` is not a member of "
            f"this workspace any more, so this axis is pointed at nothing.",
            file=sys.stderr,
        )
        return 1

    features: dict[str, list[str]] = packages[PACKAGE].get("features", {})
    if not features:
        print(
            f"feature-gate-diagnostic: FAIL -- `{PACKAGE}` declares no feature, "
            f"so this axis would pass over an empty set.",
            file=sys.stderr,
        )
        return 1
    enabled_by_default = default_closure(features)
    optional = {f for f in features if f != "default"} - enabled_by_default

    findings: list[str] = []
    if not optional:
        findings.append(
            f"`{PACKAGE}` has no feature outside its default set, so every path "
            f"is reachable from a plain build and this axis has nothing to "
            f"measure -- an empty population reads exactly like total compliance"
        )
    for feature in sorted(optional - set(PROBES) - set(NO_PUBLIC_PATH)):
        findings.append(
            f"`{PACKAGE}` declares the non-default feature `{feature}` and this "
            f"table says nothing about it. Give it a probe naming a public path "
            f"it gates, or an entry in NO_PUBLIC_PATH with the reason it gates "
            f"none -- a feature nobody decided about is the silence this axis "
            f"exists to refuse"
        )
    for feature in sorted(set(PROBES) & set(NO_PUBLIC_PATH)):
        findings.append(
            f"`{feature}` is both probed and declared to gate no public path, "
            f"and those cannot both be true"
        )
    for feature in sorted((set(PROBES) | set(NO_PUBLIC_PATH)) - optional):
        where = "a default feature" if feature in enabled_by_default else "no feature"
        findings.append(
            f"this table names `{feature}` and `{PACKAGE}` has {where} by that "
            f"name -- the row is stale"
        )
    for feature, probes in sorted(PROBES.items()):
        if not probes:
            findings.append(
                f"`{feature}` is listed as probed and carries no probe, which is "
                f"a green result over nothing"
            )

    if findings:
        print("feature-gate-diagnostic: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1

    target_dir = str(WORKSPACE / "target")
    probed = 0
    for feature in sorted(set(PROBES) & optional):
        wanted = sorted(enabled_by_default - {feature})
        for label, body in PROBES[feature]:
            rc, stderr = build_probe(feature, label, body, wanted, target_dir)
            probed += 1
            if rc == 0:
                findings.append(
                    f"`{feature}` / {label}: the probe COMPILED with the feature "
                    f"off, so the path it names is reachable without it and this "
                    f"probe has been measuring nothing"
                )
                continue
            want = NOTE.format(feature=feature)
            if want not in stderr:
                findings.append(
                    f"`{feature}` / {label}: the build failed and rustc did not "
                    f"say `{want}`, so a consumer is left to work out that a "
                    f"feature is what is missing. Either the gate moved off the "
                    f"item it configures out (a `cfg_if`, a re-export, one "
                    f"module further in), or this toolchain no longer words the "
                    f"note this way -- the compiler's output is below"
                )
                findings.append("    " + "\n    ".join(stderr.strip().splitlines()[-25:]))

    if findings:
        print("feature-gate-diagnostic: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1
    if not probed:
        print(
            "feature-gate-diagnostic: FAIL -- no probe was built, so nothing "
            "was asked of the compiler.",
            file=sys.stderr,
        )
        return 1

    others = len(packages) - 1
    print(
        f"  feature-gate-diagnostic: {len(optional)} non-default feature(s) of "
        f"{PACKAGE}, {len(NO_PUBLIC_PATH)} gating no public path, {probed} probe(s) "
        f"told by rustc which feature was missing; {others} other workspace "
        f"package(s) are NOT covered by this axis"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
