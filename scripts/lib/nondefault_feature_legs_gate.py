#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4607 (no register item) -- every non-default feature of the engine and session crates is turned
on by a leg of the non-default tests gate, or a row here says where else it is exercised.

## The defect, measured

`nondefault-tests-gate.sh --census` asks whether every TEST that only a feature build reaches is run
by a leg. It cannot ask whether every FEATURE is: a feature whose effect is a different answer from a
test that the default build already has (`limits-lent-at-open` flips one constant a default test
reads), or a feature that changes code and has no test at all (`connect-endpoints` had none), adds
no test to the census population, so the census is green while no build of any leg turns the feature
on. Read on 2026-11-23 against the five crates below, twenty declared non-default features were in
no leg: three of the session core's request slots, its endpoint list and its lent-at-open selector,
the MCU shell's token, heap client, listener and pool mark, the cooperative runtime's host-sys lock,
single-context section and pool mark, the cooperative engine's event log and host-sys form, and the
pico ABI's Zephyr, POSIX and Windows forms, its MCU scout, its multicast declarations and its secure
channel. The Zephyr form was linked by no hosted lane at all, and a broken build of it was seen only
on a run by hand.

## The population is DERIVED

For each crate of `GOVERNED`: every feature its manifest declares, minus `default` and what `default`
turns on in the crate itself. A leg of `scripts/lib/nondefault-tests-gate.sh` turns on what its
feature field names, closed under the crate's own `[features]` table, plus the crate's defaults
unless the field says `-default`. A feature is COVERED when some leg of its crate turns it on.

A feature no leg turns on is a FAILURE unless `EXEMPT` holds a row for it, and each row is checked:

* `forward` -- the feature is only a forward: the crate's sources have no `feature = "<f>"` site,
  and every feature it turns on, in this crate or in a workspace crate, is turned on by a leg of
  that crate (or is that crate's default, or is a governed crate's checked row);
* `lane` -- another lane exercises it: every (file, text) of its evidence holds, and at least one
  of those files names the feature;
* `gap` -- an acknowledged gap, with the same evidence check; printed on every run, so it is never
  read as coverage.

A row is STALE, and fails, when its feature is not declared, is a default, or is turned on by a leg:
the table can only shrink by the work it names. A leg that names a feature its crate does not declare
fails too, as cargo would refuse it, but before any build.

## What it does NOT see

Combinations. A leg turns a feature on beside the others its row names; a defect that needs one
feature on and another off is in no population here, as the header of `nondefault-tests-gate.sh`
says of the table it reads. Nor does a leg that turns a feature on prove that a test reads it: the
legs added with this gate each run a test that asserts what the feature changes, and a leg added
later is held to that by review, not by this file.

  python3 scripts/lib/nondefault_feature_legs_gate.py --check
  python3 scripts/lib/nondefault_feature_legs_gate.py --selftest
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Callable, NamedTuple, Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEGS_FILE = "scripts/lib/nondefault-tests-gate.sh"

#: The crates whose every non-default feature must be turned on by a leg or excused by a row.
GOVERNED: tuple[str, ...] = (
    "wz-capi-coop",
    "wz-capi-pico",
    "wz-runtime-coop",
    "wz-session-core",
    "wz-session-mcu",
)


class Exemption(NamedTuple):
    """Why no leg turns a feature on: `kind` is `forward`, `lane` or `gap` (the module doc)."""

    kind: str
    reason: str
    evidence: tuple[tuple[str, str], ...] = ()


EXEMPT: dict[tuple[str, str], Exemption] = {
    ("wz-capi-coop", "host-sys"): Exemption(
        "forward",
        "the host's lock and threads without `std`: wz-capi-port's `os-sys` and wz-runtime-coop's "
        "`host-lock-sys`, each turned on by a leg of its own crate",
    ),
    ("wz-session-mcu", "pool-monitor"): Exemption(
        "forward",
        "the high-water marks of the runtime's and the session core's tables, each turned on by a "
        "leg of its own crate; the shell lists the pools with or without it",
    ),
    ("wz-session-mcu", "listen"): Exemption(
        "lane",
        "a node that takes the sessions its clients open is a process: Layer Z packages the "
        "declared listening node (slot-server, built with it) and holds it against stock clients",
        (
            ("scripts/run-ci.sh", "_runci_guarded_test Zsrv"),
            ("deploy/nodes/slot-server.toml", 'role = "listen"'),
            ("deploy/host-slot-node/Cargo.toml", 'listen = ["wz-session-mcu/listen"]'),
        ),
    ),
    ("wz-capi-pico", "os-zephyr"): Exemption(
        "lane",
        "the library of a Zephyr image, which a host cannot link: Layer Qzp builds the image in "
        "both threading arms and boots one cell of it under QEMU",
        (
            ("scripts/run-ci.sh", "run_layer Qzp layer_qzp_pico_abi_mcu_image"),
            (".github/workflows/ci.yml", "bash scripts/run-ci.sh --layer Qzp"),
            ("deploy/zephyr-capi-pico/rust/Cargo.toml", '"os-zephyr"'),
        ),
    ),
    ("wz-capi-pico", "tls-mbedtls"): Exemption(
        "lane",
        "the cooperative engine's secure channel, refused beside the tokio engine every leg of "
        "this crate keeps; lane C1co runs its files (SKIPS of the tests gate say the same)",
        (("scripts/run-ci.sh", '_runci_guarded_test "C1co tls engine-coop"'),),
    ),
    ("wz-capi-pico", "os-posix"): Exemption(
        "gap",
        "the POSIX library without `std`: one step of the platform workflow builds it and runs a C "
        "program against it, and that step is observed (continue-on-error), so a red fails no run",
        (
            (".github/workflows/platform.yml", "WZ_PICO_FORM: nostd"),
            ("scripts/pico-c-program.sh", '*) host_form="os-posix" ;;'),
        ),
    ),
    ("wz-capi-pico", "os-windows"): Exemption(
        "gap",
        "the Windows library without `std`, an MSVC target's: the same observed platform step on "
        "its Windows host, so a red fails no run",
        (
            (".github/workflows/platform.yml", "WZ_PICO_FORM: nostd"),
            ("scripts/pico-c-program.sh", '*-windows-*) host_form="os-windows" ;;'),
        ),
    ),
}

KINDS = ("forward", "lane", "gap")


class Leg(NamedTuple):
    package: str
    features: tuple[str, ...]
    no_default: bool


# -- reading ------------------------------------------------------------------------------------


def _strip_comment(line: str) -> str:
    """`line` without a TOML comment; a `#` inside a string is kept."""
    quoted = False
    for i, ch in enumerate(line):
        if ch == '"':
            quoted = not quoted
        elif ch == "#" and not quoted:
            return line[:i]
    return line


_ENTRY = re.compile(r"^\s*([A-Za-z0-9_][A-Za-z0-9_-]*)\s*=\s*\[(.*?)\]", re.M | re.S)
_KEY = re.compile(r"^\s*([A-Za-z0-9_][A-Za-z0-9_-]*)\s*=", re.M)


def manifest_features(text: str) -> dict[str, list[str]]:
    """The `[features]` table of a manifest: each feature and what it turns on. Raises on a key the
    table holds that is not a list, which would be a feature this reader did not read."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == "[features]"), None)
    if start is None:
        return {}
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.lstrip().startswith("["):
            break
        body.append(_strip_comment(line))
    joined = "\n".join(body)
    out = {m.group(1): re.findall(r'"([^"]*)"', m.group(2)) for m in _ENTRY.finditer(joined)}
    keys = set(_KEY.findall(joined))
    if keys != set(out):
        raise ValueError(f"[features] keys read as no list: {sorted(keys - set(out))}")
    return out


def closure(features: dict[str, list[str]], start: list[str]) -> set[str]:
    """What `start` turns on in the crate itself: a `dep:` or `dep/feat` entry is another crate's."""
    seen: set[str] = set()
    stack = list(start)
    while stack:
        name = stack.pop()
        if name in seen or name not in features:
            continue
        seen.add(name)
        stack.extend(e for e in features[name] if not e.startswith("dep:") and "/" not in e)
    return seen


def legs(text: str) -> list[Leg]:
    """The rows of the `LEGS=(...)` table, a backslash-newline joining a row's lines as bash does."""
    m = re.search(r"(?m)^LEGS=\($(.*?)^\)$", text, re.S)
    if m is None:
        raise ValueError(f"no LEGS=( ... ) table in {LEGS_FILE}")
    body = re.sub(r"\\\n", "", m.group(1))
    out: list[Leg] = []
    for line in body.splitlines():
        row = line.strip()
        if not row.startswith('"'):
            continue
        fields = row[1 : row.rindex('"')].split("|")
        if len(fields) < 3:
            raise ValueError(f"a LEGS row of fewer than three fields: {row}")
        names = [f for f in re.sub(r"\s", "", fields[2]).split(",") if f]
        out.append(
            Leg(fields[0], tuple(n for n in names if n != "-default"), "-default" in names)
        )
    return out


# -- the tree, behind two readers so the selftest can hand it a synthetic one ---------------------


class Tree(NamedTuple):
    #: the text of a tracked file, or None when there is none
    read: Callable[[str], Optional[str]]
    #: the Rust sources of a crate, as (path, text)
    rust: Callable[[str], "list[tuple[str, str]]"]


def disk_tree(root: pathlib.Path) -> Tree:
    def read(path: str) -> Optional[str]:
        p = root / path
        return p.read_text(encoding="utf-8") if p.is_file() else None

    def rust(crate: str) -> list[tuple[str, str]]:
        base = root / "crates" / crate
        found = []
        for sub in ("src", "tests", "benches", "examples"):
            for p in sorted((base / sub).rglob("*.rs")):
                found.append((str(p.relative_to(root)), p.read_text(encoding="utf-8")))
        if (base / "build.rs").is_file():
            found.append((f"crates/{crate}/build.rs", (base / "build.rs").read_text(encoding="utf-8")))
        return found

    return Tree(read, rust)


# -- the verdict --------------------------------------------------------------------------------


class Report(NamedTuple):
    findings: list[str]
    summary: list[str]
    gaps: list[str]


def _covered(
    tree: Tree, crate: str, table: list[Leg], manifests: dict[str, dict[str, list[str]]]
) -> Optional[set[str]]:
    """What the legs of `crate` turn on in it, its defaults included; None when it has no manifest."""
    if crate not in manifests:
        text = tree.read(f"crates/{crate}/Cargo.toml")
        if text is None:
            return None
        manifests[crate] = manifest_features(text)
    feats = manifests[crate]
    on = closure(feats, feats.get("default", []))
    for leg in table:
        if leg.package != crate:
            continue
        start = list(leg.features) + ([] if leg.no_default else feats.get("default", []))
        on |= closure(feats, start)
    return on


def _feature_named(text: str, feature: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(feature)}(?![\w-])", text) is not None


def verdict(
    tree: Tree,
    governed: tuple[str, ...] = GOVERNED,
    exempt: Optional[dict[tuple[str, str], Exemption]] = None,
) -> Report:
    exempt = EXEMPT if exempt is None else exempt
    findings: list[str] = []
    summary: list[str] = []
    gaps: list[str] = []
    legs_text = tree.read(LEGS_FILE)
    if legs_text is None:
        return Report([f"{LEGS_FILE} is missing, so no feature can be held to a leg"], [], [])
    try:
        table = legs(legs_text)
    except ValueError as e:
        return Report([str(e)], [], [])
    if not table:
        return Report([f"{LEGS_FILE} has no leg: a population held to nothing is no verdict"], [], [])

    manifests: dict[str, dict[str, list[str]]] = {}
    covered: dict[str, set[str]] = {}
    nondefault: dict[str, set[str]] = {}
    for crate in governed:
        text = tree.read(f"crates/{crate}/Cargo.toml")
        if text is None:
            findings.append(f"{crate}: no manifest at crates/{crate}/Cargo.toml")
            continue
        try:
            feats = manifest_features(text)
        except ValueError as e:
            findings.append(f"{crate}: {e}")
            continue
        manifests[crate] = feats
        if not feats:
            findings.append(f"{crate}: its manifest declares no feature, so this has no input")
            continue
        defaults = closure(feats, feats.get("default", []))
        nondefault[crate] = set(feats) - defaults - {"default"}
        crate_legs = [leg for leg in table if leg.package == crate]
        if not crate_legs:
            findings.append(f"{crate}: no leg of {LEGS_FILE} runs it")
        for leg in crate_legs:
            for name in leg.features:
                if name not in feats:
                    findings.append(f"{crate}: a leg names `{name}`, which the crate does not declare")
        covered[crate] = _covered(tree, crate, table, manifests) or set()

    for (crate, feature), row in sorted(exempt.items()):
        label = f"{crate} / {feature}"
        if row.kind not in KINDS:
            findings.append(f"{label}: an exemption of kind `{row.kind}`, which is none of {KINDS}")
            continue
        if not row.reason.strip():
            findings.append(f"{label}: an exemption with no reason")
        if crate not in governed:
            findings.append(f"{label}: an exemption for a crate this gate does not govern")
            continue
        feats = manifests.get(crate)
        if feats is None:
            continue
        if feature not in feats:
            findings.append(f"{label}: an exemption for a feature the crate does not declare; drop the row")
            continue
        if feature not in nondefault.get(crate, set()):
            findings.append(f"{label}: an exemption for a default feature; drop the row")
            continue
        if feature in covered.get(crate, set()):
            findings.append(f"{label}: a leg turns it on, so the exemption is stale; drop the row")
            continue
        if row.kind == "forward":
            findings += _forward_findings(tree, crate, feature, feats, table, manifests, covered, exempt)
        else:
            findings += _evidence_findings(tree, label, feature, row)
        if row.kind == "gap":
            gaps.append(f"{label}: {row.reason}")

    for crate in governed:
        if crate not in nondefault:
            continue
        excused = {f for (c, f) in exempt if c == crate}
        for feature in sorted(nondefault[crate] - covered[crate] - excused):
            findings.append(
                f"{crate} / {feature}: no leg of {LEGS_FILE} turns it on and no row of EXEMPT says "
                f"why; add a leg whose test reads it (write the test if none does), or a row"
            )
        kinds = {k: sum(1 for (c, _), r in exempt.items() if c == crate and r.kind == k) for k in KINDS}
        summary.append(
            f"{crate}: {len(nondefault[crate])} non-default, "
            f"{len(nondefault[crate] & covered[crate])} turned on by a leg, "
            f"{kinds['forward']} forward, {kinds['lane']} lane, {kinds['gap']} gap"
        )
    return Report(findings, summary, gaps)


def _forward_findings(
    tree: Tree,
    crate: str,
    feature: str,
    feats: dict[str, list[str]],
    table: list[Leg],
    manifests: dict[str, dict[str, list[str]]],
    covered: dict[str, set[str]],
    exempt: dict[tuple[str, str], Exemption],
) -> list[str]:
    label = f"{crate} / {feature}"
    out: list[str] = []
    site = re.compile(rf'feature\s*=\s*"{re.escape(feature)}"')
    for path, text in tree.rust(crate):
        for n, line in enumerate(text.splitlines(), 1):
            if site.search(line):
                out.append(f"{label}: a forward, but {path}:{n} reads it; a leg must turn it on")
    targets: list[tuple[str, str]] = []
    for entry in feats[feature]:
        if entry.startswith("dep:"):
            continue
        if "/" in entry:
            dep, feat = entry.split("/", 1)
            targets.append((dep.rstrip("?"), feat))
        else:
            targets.append((crate, entry))
    if not targets:
        out.append(f"{label}: a forward that turns nothing on")
    for dep, feat in targets:
        on = covered.get(dep)
        if on is None:
            on = _covered(tree, dep, table, manifests)
            if on is None:
                out.append(f"{label}: forwards to {dep}/{feat}, a crate with no manifest under crates/")
                continue
            covered[dep] = on
        if feat in on:
            continue
        row = exempt.get((dep, feat))
        if row is not None and row.kind != "gap":
            continue
        out.append(f"{label}: forwards to {dep}/{feat}, which no leg of {dep} turns on")
    return out


def _evidence_findings(tree: Tree, label: str, feature: str, row: Exemption) -> list[str]:
    if not row.evidence:
        return [f"{label}: a `{row.kind}` row with no evidence"]
    out: list[str] = []
    named = False
    for path, needle in row.evidence:
        text = tree.read(path)
        if text is None:
            out.append(f"{label}: its evidence {path} is missing")
            continue
        if needle not in text:
            out.append(f"{label}: its evidence {path} no longer holds {needle!r}")
        named = named or _feature_named(text, feature)
    if not named:
        out.append(f"{label}: none of its evidence names the feature, so it is evidence of something else")
    return out


# -- the selftest -------------------------------------------------------------------------------


def _fake(files: dict[str, str], rust: Optional[dict[str, list[tuple[str, str]]]] = None) -> Tree:
    return Tree(files.get, lambda c: (rust or {}).get(c, []))


_A = """[package]
name = "a"

[features]
default = ["x"]  # the default
x = []
y = []
# a comment between entries
z = [
    "y",
    "b/q",
]
w = ["b?/q", "dep:b"]

[dependencies]
b = { path = "../b" }
"""

_B = """[features]
default = []
q = []
"""


def _legs(*rows: str) -> str:
    return "#!/usr/bin/env bash\nLEGS=(\n" + "\n".join(rows) + "\n)\n\nSKIPS=(\n)\n"


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, ok: bool, detail: object = "") -> None:
        if not ok:
            failures.append(f"{name}: {detail}")

    feats = manifest_features(_A)
    expect("features read", set(feats) == {"default", "x", "y", "z", "w"}, feats)
    expect("a list over lines", feats["z"] == ["y", "b/q"], feats["z"])
    expect("closure stays in the crate", closure(feats, ["z"]) == {"z", "y"}, closure(feats, ["z"]))
    try:
        manifest_features('[features]\nx = "not a list"\n')
        failures.append("a key that is no list is refused: it was read")
    except ValueError:
        pass

    table = legs(_legs('    "a|hook|\\', "        z,\\", '        w|mod::"', '    "b|hook|q|"'))
    expect("a row over lines", table[0] == Leg("a", ("z", "w"), False), table)
    expect("-default is a flag", legs(_legs('    "a|hook|-default,y|"'))[0].no_default, "")

    gov = ("a",)
    files = {
        "crates/a/Cargo.toml": _A,
        "crates/b/Cargo.toml": _B,
        "lane.txt": "the lane runs a with feature w",
    }
    clean = _legs('    "a|hook|z,w|"', '    "b|hook|q|"')
    report = verdict(_fake({**files, LEGS_FILE: clean}), gov, {})
    expect("the clean tree passes", report.findings == [], report.findings)
    want = ["a: 3 non-default, 3 turned on by a leg, 0 forward, 0 lane, 0 gap"]
    expect("the summary counts", report.summary == want, report.summary)

    report = verdict(_fake({**files, LEGS_FILE: _legs('    "a|hook|y|"', '    "b|hook|q|"')}), gov, {})
    both = any("a / z" in f for f in report.findings) and any("a / w" in f for f in report.findings)
    expect("a feature in no leg fails", both, report.findings)
    expect("a covered one does not", not any("a / y:" in f for f in report.findings), report.findings)

    report = verdict(_fake({**files, LEGS_FILE: _legs('    "a|hook|z,w,nope|"')}), gov, {})
    expect("a leg naming an undeclared feature fails", any("`nope`" in f for f in report.findings), report.findings)

    report = verdict(_fake({**files, LEGS_FILE: _legs()}), gov, {})
    expect("an empty table fails", any("no leg" in f for f in report.findings), report.findings)

    no_w = _legs('    "a|hook|z|"', '    "b|hook|q|"')
    fwd = {("a", "w"): Exemption("forward", "it forwards")}
    report = verdict(_fake({**files, LEGS_FILE: no_w}), gov, fwd)
    expect("a forward whose target a leg turns on passes", report.findings == [], report.findings)

    report = verdict(_fake({**files, LEGS_FILE: _legs('    "a|hook|y|"')}), gov, {("a", "z"): fwd[("a", "w")], ("a", "w"): fwd[("a", "w")]})
    expect("a forward whose target no leg turns on fails", any("forwards to b/q" in f for f in report.findings), report.findings)

    sited = _fake({**files, LEGS_FILE: no_w}, {"a": [("crates/a/src/lib.rs", '#[cfg(feature = "w")]\nfn f() {}\n')]})
    report = verdict(sited, gov, fwd)
    expect("a forward the sources read fails", any("crates/a/src/lib.rs:1" in f for f in report.findings), report.findings)

    lane = {("a", "w"): Exemption("lane", "a lane runs it", (("lane.txt", "the lane runs"),))}
    report = verdict(_fake({**files, LEGS_FILE: no_w}), gov, lane)
    expect("a lane row whose evidence holds passes", report.findings == [], report.findings)
    report = verdict(_fake({**files, LEGS_FILE: no_w, "lane.txt": "the lane runs a"}), gov, lane)
    expect("evidence that names no feature fails", any("names the feature" in f for f in report.findings), report.findings)
    report = verdict(_fake({**files, LEGS_FILE: no_w, "lane.txt": "w"}), gov, lane)
    expect("a needle that moved fails", any("no longer holds" in f for f in report.findings), report.findings)
    report = verdict(_fake({**files, LEGS_FILE: no_w}), gov, {("a", "w"): Exemption("lane", "r")})
    expect("a lane row with no evidence fails", any("no evidence" in f for f in report.findings), report.findings)

    gap = {("a", "w"): Exemption("gap", "nothing gates it", (("lane.txt", "the lane runs"),))}
    report = verdict(_fake({**files, LEGS_FILE: no_w}), gov, gap)
    expect("a gap passes and is printed", report.findings == [] and len(report.gaps) == 1, report)

    report = verdict(_fake({**files, LEGS_FILE: clean}), gov, lane)
    expect("a row for a feature a leg turns on is stale", any("stale" in f for f in report.findings), report.findings)
    stale = {("a", "gone"): Exemption("lane", "r", (("lane.txt", "the lane runs"),))}
    report = verdict(_fake({**files, LEGS_FILE: clean}), gov, stale)
    expect("a row for an undeclared feature fails", any("does not declare" in f for f in report.findings), report.findings)
    stale = {("a", "x"): Exemption("lane", "r", (("lane.txt", "the lane runs"),))}
    report = verdict(_fake({**files, LEGS_FILE: clean}), gov, stale)
    expect("a row for a default fails", any("default feature" in f for f in report.findings), report.findings)
    report = verdict(_fake({**files, LEGS_FILE: no_w}), gov, {("a", "w"): Exemption("maybe", "r")})
    expect("an unknown kind fails", any("none of" in f for f in report.findings), report.findings)

    defaultless = _legs('    "a|hook|-default,y,z,w|"', '    "b|hook|q|"')
    report = verdict(_fake({**files, LEGS_FILE: defaultless}), gov, {})
    expect("a -default leg still covers what it names", report.findings == [], report.findings)

    for line in failures:
        print(f"nondefault-feature-legs selftest FAIL: {line}", file=sys.stderr)
    if failures:
        return 1
    print("nondefault-feature-legs selftest: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="hold the tree (the default)")
    mode.add_argument("--selftest", action="store_true", help="hold this file's own rules")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    report = verdict(disk_tree(ROOT))
    for line in report.summary:
        print(f"  nondefault-feature-legs: {line}")
    for line in report.gaps:
        print(f"  nondefault-feature-legs: documented gap -- {line}")
    for line in report.findings:
        print(f"nondefault-feature-legs: FAIL -- {line}", file=sys.stderr)
    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
