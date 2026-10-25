#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3553 (no register item) -- a file of the zenoh family carries upstream's notice.

The family crates (`crates/wz-zenoh-*` and `crates/wz-zenoh`, inventory atom `api-compat-rust`)
reproduce the public API and the documentation of the crates of the same name of
eclipse-zenoh/zenoh, which are `EPL-2.0 OR Apache-2.0`. Both licenses ask the same of a derived
file: keep the copyright and license notices of the original, state that the file was changed,
and ship a copy of the license (Apache-2.0 section 4(a), (b) and (c); EPL-2.0 section 3.3). The
first slices of the family dropped the notice and put this repository's own header on the files,
which is the one thing neither license allows; the owner delegated the structure (2026-10-24) and
this gate is the part of it that stops it coming back.

## The structure, and what is judged

  * every source file of a family crate (a member of `rust_api_surface.MEMBERS`) opens with
    upstream's own notice block, kept verbatim, then `SPDX-License-Identifier: EPL-2.0 OR
    Apache-2.0`, then this repository's `SPDX-FileCopyrightText` line and a `Modified by ... Derived
    from <crate> <version>, file <path>` statement. A file whose upstream original has no notice
    says so instead and carries the declared license of its crate;
  * the manifest of a family crate declares `license = "EPL-2.0 OR Apache-2.0"`, not the
    workspace's expression;
  * `LICENSES/Apache-2.0.txt` and `LICENSES/EPL-2.0.txt` are in the tree (the license texts a
    recipient is owed);
  * no file of a family crate carries this repository's `LicenseRef-watching-zenoh` expression.

The population is DERIVED from the member table, never counted by hand, and an empty population is
a failure (a scan that found nothing to judge reports nothing wrong).

## The top crate

`zenoh` itself (`crates/wz-zenoh`) was exempt while it declared no public item, because nothing was
derived and its files kept this repository's header. It declared its first (the `bytes` module,
docs/zenoh-api-on-the-engine.md, slice Z0a), so it is in the population like every other member and
the exemption is gone: a derived file of the top crate names `zenoh` as its crate and sits in
`zenoh/src/` of upstream, where the lower crates sit in `commons/<crate>/src/`.

## The resolution arm

`--resolve` reads every `Derived from` statement and holds it to the pinned checkout: the file it
names must exist upstream, and the `Copyright (c) YYYY ZettaScale Technology` line of that file must
be the one the family file carries (a file with no such line there must say that it has none).
It needs a zenoh source tree, so it runs in the lane that provisions one, like the citation gate's
resolution arm; the default run grades the FORM and prints that it deferred this half.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import upstream_feature_census as ufc  # noqa: E402

#: The version the family reproduces, READ from the one place that holds it. A statement that names
#: another version is stale: the pin moved and the file was not re-derived.
PIN = ufc.UPSTREAM_VERSION

UPSTREAM_EXPR = "EPL-2.0 OR Apache-2.0"
OUR_EXPR_MARK = "LicenseRef-watching-zenoh"
OUR_COPYRIGHT = "SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael"
CHANGE_MARK = "Modified by newmassrael in 2026 for watching-zenoh. Derived from"
NOTICE_MARKS = (
    "Eclipse Public License 2.0 which is available at",
    "ZettaScale Zenoh Team",
)
HEADERLESS_MARKS = (
    "Copyright (c) the contributors of Eclipse zenoh",
    "carries no notice of its own",
)
LICENSE_TEXTS = {
    "LICENSES/Apache-2.0.txt": ("Apache License", 150),
    "LICENSES/EPL-2.0.txt": ("Eclipse Public License - v 2.0", 250),
}

#: Below this the scan read the wrong tree: the family is eight crates and about ninety files.
MIN_FILES = 60

HEAD_LINES = 40
DERIVED = re.compile(
    r"Derived from (zenoh(?:-[a-z]+)?) (\d+\.\d+\.\d+), file\s*(?://\s*)?([\w./-]+)"
)
UPSTREAM_COPYRIGHT = re.compile(r"Copyright \(c\) \d{4} ZettaScale Technology")


def family_dirs() -> list[str]:
    """`crates/wz-<package>` of every member of the family, from the member table."""
    import rust_api_surface as ras

    return [f"crates/wz-{m.package}" for m in ras.MEMBERS]


def upstream_file(pin: pathlib.Path, crate: str, path: str) -> pathlib.Path:
    """Where upstream keeps `path` of `crate`: the top crate is `zenoh/`, the others are under
    `commons/`."""
    return pin / (crate if crate == "zenoh" else f"commons/{crate}") / path


def tracked(root: pathlib.Path, dirs: list[str]) -> dict[str, str]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", *dirs],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout.decode()
    files: dict[str, str] = {}
    for rel in filter(None, out.split("\0")):
        if rel.endswith((".rs", "Cargo.toml")):
            files[rel] = (root / rel).read_text(encoding="utf-8", errors="replace")
    return files


def head(text: str) -> str:
    return "\n".join(text.splitlines()[:HEAD_LINES])


def flat(text: str) -> str:
    """The head with its comment line breaks closed up, so a statement wrapped over two comment
    lines is one phrase (the SPDX lines are still read line by line from `head`)."""
    return re.sub(r"\n\s*(?://|#)\s*", " ", head(text))


def judge_file(rel: str, text: str) -> list[str]:
    h = head(text)
    f = flat(text)
    errors: list[str] = []
    if rel.endswith("Cargo.toml"):
        if f"SPDX-License-Identifier: {UPSTREAM_EXPR}" not in h:
            errors.append(f"{rel}: the manifest header does not name `{UPSTREAM_EXPR}`")
        if not re.search(rf'^license\s*=\s*"{re.escape(UPSTREAM_EXPR)}"\s*$', text, re.M):
            errors.append(
                f"{rel}: the package does not declare `license = \"{UPSTREAM_EXPR}\"` "
                "(a family crate is not under the workspace's expression)"
            )
        if OUR_EXPR_MARK in text:
            errors.append(f"{rel}: carries this repository's `{OUR_EXPR_MARK}` expression")
        return errors
    if f"SPDX-License-Identifier: {UPSTREAM_EXPR}" not in h:
        errors.append(f"{rel}: the header does not name `{UPSTREAM_EXPR}`")
    if OUR_EXPR_MARK in h:
        errors.append(f"{rel}: carries this repository's `{OUR_EXPR_MARK}` expression")
    if OUR_COPYRIGHT not in h:
        errors.append(f"{rel}: lacks this repository's copyright line for its modifications")
    if CHANGE_MARK not in f:
        errors.append(f"{rel}: lacks the statement that it was modified and what it derives from")
    d = derived_from(text)
    if d is not None and d[1] != PIN:
        errors.append(f"{rel}: derives from version {d[1]} and the pin is {PIN}: re-derive it")
    kept = all(m in f for m in NOTICE_MARKS)
    headerless = all(m in f for m in HEADERLESS_MARKS)
    if not (kept or headerless):
        errors.append(
            f"{rel}: carries neither upstream's notice block (the Eclipse license paragraph and "
            "its Contributors line) nor the statement that the upstream file has none"
        )
    return errors


def judge(
    files: dict[str, str],
    licenses: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    if len(files) < MIN_FILES:
        errors.append(
            f"only {len(files)} family file(s) read, under {MIN_FILES}: the scan read the wrong "
            "tree or the member table lost its crates; an empty population is not a pass"
        )
    for rel in sorted(files):
        errors.extend(judge_file(rel, files[rel]))
    for rel, (mark, min_lines) in LICENSE_TEXTS.items():
        text = licenses.get(rel)
        if text is None:
            errors.append(f"{rel}: the license text a recipient is owed is not in the tree")
        elif mark not in text or len(text.splitlines()) < min_lines:
            errors.append(f"{rel}: is not the text of the license (`{mark}`, at least {min_lines} lines)")
    return errors


def derived_from(text: str) -> tuple[str, str, str] | None:
    m = DERIVED.search(flat(text))
    return (m.group(1), m.group(2), m.group(3)) if m else None


def resolve(files: dict[str, str], pin: pathlib.Path) -> list[str]:
    """Hold each `Derived from` statement to the pinned checkout."""
    errors: list[str] = []
    for rel in sorted(files):
        if not rel.endswith(".rs"):
            continue
        text = files[rel]
        d = derived_from(text)
        if d is None:
            errors.append(f"{rel}: no `Derived from <crate> <version>, file <path>` statement to resolve")
            continue
        crate, _version, path = d
        up = upstream_file(pin, crate, path)
        if not up.is_file():
            errors.append(f"{rel}: derives from `{crate}` file `{path}`, which is not at the pin")
            continue
        upstream_lines = UPSTREAM_COPYRIGHT.findall(head(up.read_text(encoding="utf-8", errors="replace")))
        h = flat(text)
        if upstream_lines:
            for line in upstream_lines:
                if line not in h:
                    errors.append(f"{rel}: upstream's `{line}` is not kept")
        elif not all(m in h for m in HEADERLESS_MARKS):
            errors.append(
                f"{rel}: the upstream file has no copyright line, and this file does not say so"
            )
    return errors


def check(do_resolve: bool) -> int:
    files = tracked(REPO_ROOT, family_dirs())
    licenses = {
        rel: (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for rel in LICENSE_TEXTS
        if (REPO_ROOT / rel).is_file()
    }
    errors = judge(files, licenses)
    deferred = ""
    if do_resolve:
        import upstream_citation_anchor_gate as ucag

        pin = ucag.upstream_root()
        if pin is None:
            errors.append("--resolve asked and no zenoh checkout at the pinned version was found")
        else:
            errors.extend(resolve(files, pin))
    else:
        deferred = (
            "; the resolution arm (does each statement match upstream at the pin?) is DEFERRED "
            "to the lane that provisions the checkout (--resolve)"
        )
    if errors:
        print("family-notice gate: FAIL", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    print(
        f"family-notice gate: OK ({len(files)} file(s) of {len(family_dirs())} family crate(s) carry "
        f"upstream's notice and `{UPSTREAM_EXPR}`; "
        f"{len(licenses)} license text(s) present{deferred})"
    )
    return 0


NOTICE_BLOCK = (
    "//\n// Copyright (c) 2023 ZettaScale Technology\n//\n"
    "// This program and the accompanying materials are made available under the\n"
    "// terms of the Eclipse Public License 2.0 which is available at\n"
    "// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0\n"
    "// which is available at https://www.apache.org/licenses/LICENSE-2.0.\n//\n"
    f"// SPDX-License-Identifier: {UPSTREAM_EXPR}\n//\n"
    "// Contributors:\n//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>\n//\n"
    f"// {OUR_COPYRIGHT}\n"
    f"// {CHANGE_MARK} zenoh-x {PIN}, file\n"
    f"// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag {PIN}).\n"
)
MANIFEST = (
    f"# SPDX-License-Identifier: {UPSTREAM_EXPR}\n"
    f"# {OUR_COPYRIGHT}\n[package]\nname = \"zenoh-x\"\n"
    f'license = "{UPSTREAM_EXPR}"\n'
)


def selftest() -> int:
    lic = {
        "LICENSES/Apache-2.0.txt": "Apache License\n" + "x\n" * 200,
        "LICENSES/EPL-2.0.txt": "Eclipse Public License - v 2.0\n" + "x\n" * 300,
    }

    def population(overrides: dict[str, str] | None = None) -> dict[str, str]:
        files = {f"crates/wz-zenoh-x/src/f{i}.rs": NOTICE_BLOCK + "fn f() {}\n" for i in range(MIN_FILES)}
        files["crates/wz-zenoh-x/Cargo.toml"] = MANIFEST
        files.update(overrides or {})
        return files

    first = "crates/wz-zenoh-x/src/f0.rs"
    headerless = (
        "//\n// Copyright (c) the contributors of Eclipse zenoh (see the NOTICE)\n//\n"
        f"// SPDX-License-Identifier: {UPSTREAM_EXPR}\n//\n// {OUR_COPYRIGHT}\n"
        f"// {CHANGE_MARK} zenoh-x {PIN}, file\n// src/a.rs (https://github.com/eclipse-zenoh/zenoh, "
        f"tag {PIN}), which carries no notice of its own; the declared license applies.\n"
    )
    top_block = NOTICE_BLOCK.replace("zenoh-x", "zenoh")
    red = {
        "own expression kept": (
            population({first: NOTICE_BLOCK.replace(UPSTREAM_EXPR, OUR_EXPR_MARK + "-NonCommercial-1.0")}),
            lic,
        ),
        "no upstream expression": (
            population({first: NOTICE_BLOCK.replace(f"SPDX-License-Identifier: {UPSTREAM_EXPR}\n", "")}),
            lic,
        ),
        "no own copyright line": (population({first: NOTICE_BLOCK.replace(OUR_COPYRIGHT, "x")}), lic),
        "no change statement": (population({first: NOTICE_BLOCK.replace(CHANGE_MARK, "Edited")}), lic),
        "notice block dropped": (
            population({first: NOTICE_BLOCK.replace("ZettaScale Zenoh Team", "the team")}),
            lic,
        ),
        "manifest workspace license": (
            population({"crates/wz-zenoh-x/Cargo.toml": MANIFEST.replace(f'license = "{UPSTREAM_EXPR}"', "license.workspace = true")}),
            lic,
        ),
        "manifest own header": (
            population({"crates/wz-zenoh-x/Cargo.toml": MANIFEST + f"# {OUR_EXPR_MARK}-Commercial\n"}),
            lic,
        ),
        "license text missing": (population(), {k: v for k, v in lic.items() if "EPL" not in k}),
        "license text truncated": (population(), dict(lic, **{"LICENSES/EPL-2.0.txt": "Eclipse Public License - v 2.0\n"})),
        "empty population": ({}, lic),
        "a version that is not the pin": (
            population({first: NOTICE_BLOCK.replace(f"zenoh-x {PIN}", "zenoh-x 0.0.1")}),
            lic,
        ),
        "the top crate with this repository's header": (
            population({"crates/wz-zenoh/src/lib.rs": "// SPDX-License-Identifier: LicenseRef-watching-zenoh-X\n"}),
            lic,
        ),
        "the top crate with a version that is not the pin": (
            population({"crates/wz-zenoh/src/lib.rs": top_block.replace(f"zenoh {PIN}", "zenoh 0.0.1")}),
            lic,
        ),
    }
    failures = []
    for name, (files, lc) in red.items():
        if not judge(files, lc):
            failures.append(f"RED case {name!r} passed")
    green = judge(population({"crates/wz-zenoh-x/src/f1.rs": headerless}), lic)
    if green:
        failures.append(f"GREEN case reddened: {green}")
    green_top = judge(population({"crates/wz-zenoh/src/lib.rs": top_block}), lic)
    if green_top:
        failures.append(f"GREEN case (the top crate) reddened: {green_top}")

    # The resolution arm, against a fake pin.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        pin = pathlib.Path(tmp)
        (pin / "commons" / "zenoh-x" / "src").mkdir(parents=True)
        (pin / "commons" / "zenoh-x" / "src" / "lib.rs").write_text(NOTICE_BLOCK)
        (pin / "commons" / "zenoh-x" / "src" / "a.rs").write_text("fn a() {}\n")
        (pin / "zenoh" / "src").mkdir(parents=True)
        (pin / "zenoh" / "src" / "lib.rs").write_text(top_block)
        ok = {"crates/wz-zenoh-x/src/lib.rs": NOTICE_BLOCK}
        if resolve(ok, pin):
            failures.append(f"GREEN resolve case reddened: {resolve(ok, pin)}")
        ok_top = {"crates/wz-zenoh/src/lib.rs": top_block}
        if resolve(ok_top, pin):
            failures.append(f"GREEN resolve case (the top crate) reddened: {resolve(ok_top, pin)}")
        top_in_commons = {"crates/wz-zenoh/src/gone.rs": top_block.replace("src/lib.rs", "src/gone.rs")}
        if not resolve(top_in_commons, pin):
            failures.append("RED resolve case 'a top crate file that is not at the pin' passed")
        wrong_year = {"crates/wz-zenoh-x/src/lib.rs": NOTICE_BLOCK.replace("2023", "2024")}
        if not resolve(wrong_year, pin):
            failures.append("RED resolve case 'a year that is not upstream's' passed")
        gone = {"crates/wz-zenoh-x/src/lib.rs": NOTICE_BLOCK.replace("src/lib.rs", "src/gone.rs")}
        if not resolve(gone, pin):
            failures.append("RED resolve case 'a file that is not at the pin' passed")
        silent = {"crates/wz-zenoh-x/src/a.rs": NOTICE_BLOCK.replace("src/lib.rs", "src/a.rs")}
        if not resolve(silent, pin):
            failures.append("RED resolve case 'upstream has no line and this file claims one' passed")
        if resolve({"crates/wz-zenoh-x/src/a.rs": headerless}, pin):
            failures.append(f"GREEN resolve case (headerless) reddened: {resolve({'crates/wz-zenoh-x/src/a.rs': headerless}, pin)}")
        nostmt = {"crates/wz-zenoh-x/src/lib.rs": "// nothing\n"}
        if not resolve(nostmt, pin):
            failures.append("RED resolve case 'no statement' passed")
    if failures:
        print("family-notice gate selftest: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"family-notice gate selftest: OK ({len(red)} red case(s) red, 2 green cases green, "
        "6 red and 3 green resolve cases)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="zenoh family notice gate")
    parser.add_argument("--check", action="store_true", help="judge this tree")
    parser.add_argument("--resolve", action="store_true", help="with --check: hold the statements to the pin")
    parser.add_argument("--selftest", action="store_true", help="drive fixtures")
    args = parser.parse_args(argv)
    if args.check == args.selftest:
        parser.error("pass exactly one of --check / --selftest")
    if args.resolve and not args.check:
        parser.error("--resolve goes with --check")
    if args.selftest:
        return selftest()
    return check(args.resolve)


if __name__ == "__main__":
    sys.exit(main())
