#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3733 (no register item) -- the feature model a crate's state machines are gated by, derived from
the crate's own cargo features (docs/upstream-parity.md decision D7, SCE's ADR 0057).

## What this is

SCE gates an element of a state machine on a feature (`sce:requires="P"`, P a name, `all(..)` or
`any(..)`), and its Rust backend emits the gated item under `#[cfg(feature = "...")]`. That `cfg` is
read by the crate that compiles the generated module, so the names a machine may gate on are
exactly that crate's cargo features, and the implications between them are the crate's own
(`a = ["b"]`). The feature model is the document SCE reads them from (`sce:kind="feature-model"`,
one `<sce:feature name requires>` per feature), imported by every machine the crate compiles.

The crate's `Cargo.toml` is therefore the source, and the model is GENERATED from it, never
written by hand: a model that drifted from the manifest would let a machine gate on a feature
the crate does not have (a `cfg` that is never true) or miss an implication (a `compile_error!`
guard SCE emits for a requires edge that cargo would not enforce).

## What is left out, and said so

* `default`: cargo's default set, not a capability anything is gated on;
* a feature whose name SCE cannot spell (`[a-z][a-z0-9]*(-[a-z0-9]+)*`; `no_std` is one): a
  machine cannot gate on it, and the model's header lists it;
* an implication that names another crate (`dep:x`, `x/y`, `x?/y`): that is the crate's link to
  another manifest, not an edge between two features of this one.

Usage:
    sce_feature_model.py --emit CRATE    print the model of CRATE
    sce_feature_model.py --write         write every model in MODELS
    sce_feature_model.py --check         every model in MODELS is the one this generates
    sce_feature_model.py --selftest
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The crates whose generated state machines are gated, and where each one's model lives. A crate
#: joins when it compiles a machine from `sources/`; `wz-session-core` compiles all six today.
MODELS: dict[str, str] = {
    "wz-session-core": "sources/features/wz-session-core.scxml",
}

#: The name SCE accepts for a feature (ADR 0057, section 2).
NAME = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*\Z")

HEADER = """<?xml version="1.0" encoding="UTF-8"?>
<!--
  SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
  SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->
<!--
  GENERATED from crates/{crate}/Cargo.toml by scripts/lib/sce_feature_model.py --write.
  Do not edit: `sce_feature_model.py --check` fails when this file is stale.

  The features the state machines {crate} compiles may be gated on (SCE's ADR 0057,
  docs/upstream-parity.md decision D7): the crate's cargo features, each with the features of
  the same crate it implies. Left out: `default`{skipped}.
-->
"""


def workspace_features() -> dict[str, dict[str, list[str]]]:
    """Every workspace crate's `[features]`, as cargo reads them (`cargo metadata`), so the model
    is the manifest cargo builds from and not a second reader's idea of it."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
        cwd=ROOT / "crates", capture_output=True, text=True, check=True,
    ).stdout
    return {p["name"]: p["features"] for p in json.loads(out)["packages"]}


def model(crate: str, features: dict[str, list[str]]) -> tuple[str, list[str]]:
    """The model document of `crate`, and the features it could not carry."""
    skipped = sorted(f for f in features if f != "default" and not NAME.match(f))
    carried = {f for f in features if f != "default" and NAME.match(f)}
    lines = []
    for name in sorted(carried):
        requires = sorted({e for e in features[name] if e in carried})
        attr = f' requires="{" ".join(requires)}"' if requires else ""
        lines.append(f'  <sce:feature name="{name}"{attr}/>')
    skipped_text = "".join(f", `{s}` (a name SCE cannot spell)" for s in skipped)
    doc = (HEADER.format(crate=crate, skipped=skipped_text)
           + '<scxml xmlns="http://www.w3.org/2005/07/scxml" xmlns:sce="http://sce.dev/ext"\n'
           + f'       version="1.0" sce:kind="feature-model" name="{crate}">\n'
           + "\n".join(lines) + "\n</scxml>\n")
    return doc, skipped


def cycle(features: dict[str, list[str]]) -> list[str] | None:
    """A cycle of implications among the carried features, which SCE refuses; None when there is
    none. Cargo refuses one too, so a cycle here means the manifest did not build."""
    carried = {f for f in features if f != "default" and NAME.match(f)}
    edges = {f: [e for e in features[f] if e in carried] for f in carried}
    state: dict[str, int] = {}
    path: list[str] = []

    def visit(node: str) -> list[str] | None:
        state[node] = 1
        path.append(node)
        for nxt in edges[node]:
            if state.get(nxt) == 1:
                return path[path.index(nxt):] + [nxt]
            if nxt not in state:
                found = visit(nxt)
                if found:
                    return found
        path.pop()
        state[node] = 2
        return None

    for node in sorted(carried):
        if node not in state:
            found = visit(node)
            if found:
                return found
    return None


def generated(crate: str, workspace: dict[str, dict[str, list[str]]] | None = None) -> str:
    features = (workspace if workspace is not None else workspace_features())[crate]
    found = cycle(features)
    if found:
        raise ValueError(f"{crate}: the features imply one another in a cycle: {' -> '.join(found)}")
    return model(crate, features)[0]


def cmd_check() -> int:
    fails = 0
    workspace = workspace_features()
    for crate, path in MODELS.items():
        target = ROOT / path
        want = generated(crate, workspace)
        if not target.is_file():
            print(f"  sce-feature-model FAIL: {path} is missing: sce_feature_model.py --write")
            fails += 1
        elif target.read_text() != want:
            print(f"  sce-feature-model FAIL: {path} is not the model crates/{crate}/Cargo.toml "
                  f"gives: sce_feature_model.py --write, and commit it with the manifest")
            fails += 1
        else:
            print(f"  sce-feature-model: OK {path} is the model of crates/{crate}/Cargo.toml")
    return 1 if fails else 0


def cmd_write() -> int:
    workspace = workspace_features()
    for crate, path in MODELS.items():
        target = ROOT / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(generated(crate, workspace))
        print(f"  sce-feature-model: wrote {path}")
    return 0


def selftest() -> int:
    fails = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal fails
        print(f"  sce-feature-model selftest: {'ok  ' if cond else 'FAIL'} {name}")
        fails += not cond

    features = {
        "default": ["alloc"],
        "alloc": [],
        "no_std": ["dep:portable-atomic"],
        "session-unicast": ["alloc", "dep:sha2", "wz-codecs/alloc"],
        "session-unicast-accept": ["session-unicast", "other?/x"],
    }
    doc, skipped = model("demo", features)
    expect("default is not a feature of the model", 'name="default"' not in doc)
    expect("a name SCE cannot spell is left out and named", skipped == ["no_std"]
           and "`no_std` (a name SCE cannot spell)" in doc)
    expect("an implication within the crate is a requires edge",
           '<sce:feature name="session-unicast-accept" requires="session-unicast"/>' in doc)
    expect("an edge to another crate or a dependency is not",
           '<sce:feature name="session-unicast" requires="alloc"/>' in doc)
    expect("a feature that implies nothing has no requires", '<sce:feature name="alloc"/>' in doc)
    expect("the document is a feature model", 'sce:kind="feature-model" name="demo"' in doc)
    expect("no cycle in an acyclic manifest", cycle(features) is None)
    expect("a cycle is found", cycle({"a": ["b"], "b": ["c"], "c": ["a"]}) == ["a", "b", "c", "a"])
    expect("every model's crate is a crate of the workspace",
           all((ROOT / "crates" / c / "Cargo.toml").is_file() for c in MODELS))
    print(f"  sce-feature-model selftest: {'PASS' if not fails else f'{fails} FAIL'}")
    return 1 if fails else 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--check"]:
        return cmd_check()
    if argv == ["--write"]:
        return cmd_write()
    if len(argv) == 2 and argv[0] == "--emit":
        print(generated(argv[1]), end="")
        return 0
    print(__doc__.split("Usage:")[1], file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
