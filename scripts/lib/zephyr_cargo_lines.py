#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3439 (no register item) -- what each Zephyr image asks cargo for, read from its own build.

Step 1 of docs/build-configuration.md moves the images' hand-written Kconfig choices and their
hand-written mapping to cargo into the one declaration and its generated bridge, and it is done
only when every existing image builds with the same features and environment as before. This is
the instrument of that comparison: it configures each image of the board table
(`deploy/zephyr-boards.json`) with `west build --cmake-only` and reads the cargo command the
build recorded in its `build.ninja`, which is the command that will run, not a reading of the
CMake that makes it.

    --capture OUT    configure every image and write their cargo lines to OUT (JSON)
    --compare BASE   configure every image and report each line that differs from BASE
    --selftest       the parser and the comparison on recorded commands

The population is every row of the table whose application builds its Rust through
`wz_zephyr_rust_app` (deploy/zephyr-common/wz_zephyr_board.cmake), whatever its grade, with the
row's own overlays: a row is an image somebody builds, and a QEMU or DECLARED row is as much one
as a HARDWARE row. To it are added the stacks the overlays document: an overlay's header says how
it is built (`west build ... -- -DEXTRA_CONF_FILE="..."`), and each such stack that no row
builds is an image too, on the board of the rows that use its overlays. A stack that names a file
the application does not have (an example's `mine.conf`) is not one. An overlay neither a row nor
a stack builds is printed as not covered. An empty population fails.

A line is the Rust target, the manifest, whether the crate's default features are off, the
features (sorted), and the environment the cargo build is given (sorted), each path under the
checkout written relative to it: what cargo is asked for, with nothing of where the build ran.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TABLE = ROOT / "deploy" / "zephyr-boards.json"
ZEPHYR_BASE = pathlib.Path(os.environ.get("WZ_ZEPHYR_BASE", pathlib.Path.home() / "zephyrproject" / "zephyr"))
ZEPHYR_VENV = pathlib.Path(os.environ.get("WZ_ZEPHYR_VENV", pathlib.Path.home() / "zephyrproject" / ".venv"))
BUILD_ROOT = ROOT / "target" / "zephyr-cargo-lines"
RUST_APP_CALL = "wz_zephyr_rust_app("


def builds_rust(app: str, root: pathlib.Path = ROOT) -> bool:
    cmake = root / "deploy" / app / "CMakeLists.txt"
    return cmake.is_file() and RUST_APP_CALL in cmake.read_text(encoding="utf-8")


STACK_CONF_RE = re.compile(r'-DEXTRA_CONF_FILE="?([^"\s\\]+)"?')
STACK_DTC_RE = re.compile(r'-DEXTRA_DTC_OVERLAY_FILE="?([^"\s\\]+)"?')


def documented_stacks(app: str, rows: list[dict], root: pathlib.Path = ROOT) -> list[dict]:
    """The stacks the overlays of `app` document in their headers, as rows (see the module doc).

    Raises `ValueError` for a stack whose overlays the table's rows put on more than one board,
    or on none: where it is built is then not a fact the table states.
    """
    overlays = root / "deploy" / app / "overlays"
    if not overlays.is_dir():
        return []
    out = []
    for conf in sorted(overlays.glob("*.conf")):
        header = "\n".join(line for line in conf.read_text(encoding="utf-8").splitlines()
                           if line.startswith("#"))
        found = STACK_CONF_RE.search(header)
        if not found:
            continue
        stack = found.group(1).split(";")
        if not all((root / "deploy" / app / name).is_file() for name in stack):
            continue
        dtc = STACK_DTC_RE.search(header)
        dtc_stack = dtc.group(1).split(";") if dtc else []
        boards = {r["board"] for r in rows
                  if r["app"] == app and set(r.get("conf_overlay", [])) & set(stack)}
        if len(boards) != 1:
            raise ValueError(f"deploy/{app}/overlays/{conf.name} documents a stack the table's rows "
                             f"put on {len(boards)} board(s) ({sorted(boards)})")
        out.append({"app": app, "board": boards.pop(), "link": f"stack of {conf.name}",
                    "conf_overlay": stack, "dtc_overlay": dtc_stack})
    return out


def population(table: dict, root: pathlib.Path = ROOT) -> list[dict]:
    """The rows whose application builds its Rust through the shared function, and the stacks
    their overlays document that no row builds."""
    rows = [r for r in table["rows"] if builds_rust(r["app"], root)]
    built = {(r["app"], r["board"], tuple(r.get("conf_overlay", [])), tuple(r.get("dtc_overlay", [])))
             for r in rows}
    stacks = []
    for app in sorted({r["app"] for r in rows}):
        for stack in documented_stacks(app, rows, root):
            key = (stack["app"], stack["board"], tuple(stack["conf_overlay"]), tuple(stack["dtc_overlay"]))
            if key not in built:
                built.add(key)
                stacks.append(stack)
    return rows + stacks


def label_of(row: dict) -> str:
    return f"{row['app']} {row['board']} {row['link']}"


def uncovered_overlays(rows: list[dict]) -> list[str]:
    """The `.conf` overlays of each application in the population that no image builds."""
    named = {(r["app"], o) for r in rows for o in r.get("conf_overlay", [])}
    out = []
    for app in sorted({r["app"] for r in rows}):
        overlays = ROOT / "deploy" / app / "overlays"
        if not overlays.is_dir():
            continue
        for conf in sorted(overlays.glob("*.conf")):
            rel = f"overlays/{conf.name}"
            if (app, rel) not in named:
                out.append(f"deploy/{app}/{rel}")
    return out


def parse_cargo_command(ninja_text: str, root: pathlib.Path) -> dict:
    """The cargo build the image's `build.ninja` records, as a line (see the module doc).

    Raises `ValueError` when there is not exactly one `cargo build`, or when its arguments are
    not the shape `wz_zephyr_rust_app` writes.
    """
    commands = [
        line.split("=", 1)[1].strip()
        for line in ninja_text.splitlines()
        if line.lstrip().startswith("COMMAND =") and " cargo build " in f" {line} "
    ]
    if len(commands) != 1:
        raise ValueError(f"expected one cargo build in build.ninja, found {len(commands)}")
    words = shlex.split(commands[0])
    # The command is `cd DIR && cmake -E env VAR=VAL... cargo build ARGS...`, perhaps followed
    # by `&& ...`: take the part from `cmake -E env` up to the next `&&`.
    start = next((i for i in range(len(words) - 2) if words[i:i + 3] == ["cmake", "-E", "env"]
                  or (words[i].endswith("/cmake") and words[i + 1:i + 3] == ["-E", "env"])), None)
    if start is None:
        raise ValueError("the cargo build is not run under `cmake -E env`")
    rest = words[start + 3:]
    if "&&" in rest:
        rest = rest[:rest.index("&&")]
    cargo = rest.index("cargo") if "cargo" in rest else -1
    if cargo < 0 or rest[cargo + 1:cargo + 2] != ["build"]:
        raise ValueError("no `cargo build` after the environment")
    prefix = str(root).rstrip("/") + "/"
    env = sorted(word.replace(prefix, "") for word in rest[:cargo])
    args = rest[cargo + 2:]
    line: dict = {"target": None, "manifest": None, "no_default_features": False,
                  "features": [], "env": env}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--release":
            pass
        elif arg == "--target":
            i += 1
            line["target"] = args[i]
        elif arg == "--manifest-path":
            i += 1
            manifest = pathlib.Path(args[i])
            line["manifest"] = str(manifest.relative_to(root)) if manifest.is_absolute() else str(manifest)
        elif arg == "--no-default-features":
            line["no_default_features"] = True
        elif arg == "--features":
            i += 1
            line["features"].extend(f for f in args[i].split(",") if f)
        else:
            raise ValueError(f"a cargo argument this reader does not know: {arg!r}")
        i += 1
    line["features"] = sorted(line["features"])
    return line


def configure(row: dict, index: int) -> pathlib.Path:
    """`west build --cmake-only` of one row, into its own directory; the build directory."""
    build = BUILD_ROOT / str(index)
    cmd = [str(ZEPHYR_VENV / "bin" / "west"), "build", "--cmake-only", "-p", "always",
           "-b", row["board"], "-d", str(build), str(ROOT / "deploy" / row["app"])]
    extra = []
    if row.get("conf_overlay"):
        extra.append("-DEXTRA_CONF_FILE=" + ";".join(row["conf_overlay"]))
    if row.get("dtc_overlay"):
        extra.append("-DEXTRA_DTC_OVERLAY_FILE=" + ";".join(row["dtc_overlay"]))
    if extra:
        cmd += ["--", *extra]
    env = dict(os.environ, ZEPHYR_BASE=str(ZEPHYR_BASE))
    done = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    log = BUILD_ROOT / f"{index}.log"
    log.write_text(done.stdout + done.stderr, encoding="utf-8")
    if done.returncode != 0:
        raise RuntimeError(f"{label_of(row)}: west build --cmake-only failed (rc {done.returncode}); see {log}")
    return build


def capture(rows: list[dict]) -> dict[str, dict]:
    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    lines: dict[str, dict] = {}
    for index, row in enumerate(rows):
        build = configure(row, index)
        lines[label_of(row)] = parse_cargo_command((build / "build.ninja").read_text(encoding="utf-8"), ROOT)
    return lines


def compare(base: dict[str, dict], now: dict[str, dict]) -> list[str]:
    out = []
    for label in sorted(set(base) | set(now)):
        if label not in now:
            out.append(f"{label}: in the baseline, not built now")
        elif label not in base:
            out.append(f"{label}: built now, not in the baseline")
        else:
            for key in ("target", "manifest", "no_default_features", "features", "env"):
                if base[label].get(key) != now[label].get(key):
                    out.append(f"{label}: {key} was {base[label].get(key)!r}, now {now[label].get(key)!r}")
    return out


def cmd_selftest() -> int:
    ok = bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  zephyr-cargo-lines selftest FAIL: {name}", file=sys.stderr)

    root = pathlib.Path("/r")
    good = ("build x: CUSTOM_COMMAND\n  COMMAND = cd /r/deploy/a && /usr/bin/cmake -E env "
            "WZ_B=2 WZ_A=1 cargo build --release --target thumbv7m-none-eabi --manifest-path "
            "/r/deploy/a/rust/Cargo.toml --no-default-features --features z,y\n")
    line = parse_cargo_command(good, root)
    expect("a command is read into its parts", line == {
        "target": "thumbv7m-none-eabi", "manifest": "deploy/a/rust/Cargo.toml",
        "no_default_features": True, "features": ["y", "z"], "env": ["WZ_A=1", "WZ_B=2"]})
    expect("what follows `&&` is not the cargo build's",
           parse_cargo_command(good.rstrip("\n") + " && touch done\n", root) == line)

    def refuses(text: str) -> bool:
        try:
            parse_cargo_command(text, root)
        except ValueError:
            return True
        return False

    expect("no cargo build is refused", refuses("  COMMAND = true\n"))
    expect("two cargo builds are refused", refuses(good + good))
    expect("an argument the reader does not know is refused",
           refuses(good.replace("--release", "--release --locked")))
    expect("a cargo build outside `cmake -E env` is refused",
           refuses("  COMMAND = cd /r && cargo build --release\n"))
    moved = dict(line, features=["y"])
    expect("a changed feature list is reported",
           compare({"r": line}, {"r": moved}) == [f"r: features was ['y', 'z'], now ['y']"])
    expect("a lost row is reported", compare({"r": line}, {}) == ["r: in the baseline, not built now"])
    expect("an equal capture reports nothing", compare({"r": line}, {"r": dict(line)}) == [])
    expect("a row whose application builds no Rust is outside the population",
           population({"rows": [{"app": "no-such-app", "board": "b", "link": "l"}]}) == [])
    with_path = good.replace("WZ_A=1", "WZ_A=/r/deploy/a/port")
    expect("a path under the checkout is written relative to it",
           "WZ_A=deploy/a/port" in parse_cargo_command(with_path, root)["env"])

    with tempfile.TemporaryDirectory() as tmp:
        fake = pathlib.Path(tmp)
        app = fake / "deploy" / "img"
        (app / "overlays").mkdir(parents=True)
        (app / "CMakeLists.txt").write_text(RUST_APP_CALL + ")\n", encoding="utf-8")
        (app / "overlays" / "a.conf").write_text("X=y\n", encoding="utf-8")
        (app / "overlays" / "b.conf").write_text(
            '#   west build ... -- -DEXTRA_CONF_FILE="overlays/a.conf;overlays/b.conf" \\\n'
            '#                     -DEXTRA_DTC_OVERLAY_FILE="overlays/a.overlay"\nY=y\n', encoding="utf-8")
        (app / "overlays" / "c.conf").write_text(
            '#   west build ... -- -DEXTRA_CONF_FILE="overlays/c.conf;mine.conf"\n', encoding="utf-8")
        row = {"app": "img", "board": "kit", "link": "l", "conf_overlay": ["overlays/a.conf"]}
        stacks = documented_stacks("img", [row], fake)
        expect("a documented stack is read, with its devicetree overlay, on its rows' board",
               stacks == [{"app": "img", "board": "kit", "link": "stack of b.conf",
                           "conf_overlay": ["overlays/a.conf", "overlays/b.conf"],
                           "dtc_overlay": ["overlays/a.overlay"]}])
        other = dict(row, board="other", link="m", conf_overlay=["overlays/b.conf"])
        try:
            documented_stacks("img", [row, other], fake)
            two_boards = False
        except ValueError:
            two_boards = True
        expect("a stack whose overlays sit on two boards is refused", two_boards)
        same = {"app": "img", "board": "kit", "link": "r",
                "conf_overlay": ["overlays/a.conf", "overlays/b.conf"],
                "dtc_overlay": ["overlays/a.overlay"]}
        expect("a stack a row already builds is not built twice",
               len(population({"rows": [row, same]}, fake)) == 2)
    print(f"  zephyr-cargo-lines selftest: {ok}/{ok + bad} arm(s) pass")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--capture", type=pathlib.Path)
    mode.add_argument("--compare", type=pathlib.Path)
    mode.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        return cmd_selftest()
    try:
        rows = population(json.loads(TABLE.read_text(encoding="utf-8")))
    except ValueError as exc:
        print(f"  zephyr-cargo-lines FAIL: {exc}", file=sys.stderr)
        return 1
    if not rows:
        print("  zephyr-cargo-lines FAIL: no row of the board table builds Rust", file=sys.stderr)
        return 1
    for overlay in uncovered_overlays(rows):
        print(f"  zephyr-cargo-lines: not covered, no row names {overlay}")
    try:
        lines = capture(rows)
    except (RuntimeError, ValueError) as exc:
        print(f"  zephyr-cargo-lines FAIL: {exc}", file=sys.stderr)
        return 1
    if args.capture:
        args.capture.write_text(json.dumps(lines, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"  zephyr-cargo-lines: {len(lines)} image(s) captured to {args.capture}")
        return 0
    differences = compare(json.loads(args.compare.read_text(encoding="utf-8")), lines)
    for difference in differences:
        print(f"  zephyr-cargo-lines DIFFERS: {difference}", file=sys.stderr)
    if differences:
        return 1
    print(f"  zephyr-cargo-lines: {len(lines)} image(s), every cargo line as in {args.compare}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
