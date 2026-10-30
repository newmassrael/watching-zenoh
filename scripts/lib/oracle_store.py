#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3961 (no register item) — a zenohd oracle is a fact about a MACHINE, and it
was stored as a fact about one CHECKOUT.

## The defect, measured

`scripts/build-zenohd.sh` cloned, built and installed into the checkout's own
`target/` (`target/zenohd-build/`, `target/zenohd/`). A build machine of the
fleet runs this repository in several checkout slots (`~/checkouts/<key>/<n>`,
the lowest free one per run), and each slot has its own `target/`. Measured on
2026-10-30: slot 1 of a build machine held a zenohd at the pin after an
11-minute build from the pinned tag, and the next run, placed in slot 2, found
none at all (`oracle-pin-gate: ABSENT` four times, "checked NOTHING"). Every
slot, and every worktree of a developer's machine, paid the clone and the build
again, or ran its interop lanes with no oracle.

## The structure

A store per machine holds what was built, keyed by what determines it:

    <store>/zenohd/<version>/src                      the clone of the pinned tag
    <store>/zenohd/<version>/build/<oracle>           cargo's target dir, per oracle
    <store>/zenohd/<version>/products/<oracle>-<recipe>  the installed oracle

`<recipe>` is the digest of `build-zenohd.sh`, which alone decides what an
oracle directory contains. `<store>` is `$WZ_ORACLE_STORE`, else
`$XDG_CACHE_HOME/watching-zenoh/oracles`, else `~/.cache/...`: a path of the
machine and never of the tree (the CLAUDE.md rule on absolute paths).

`target/zenohd*` stays what every consumer reads (the test helpers of
wz-integration-tests, the census, the pin gate, the hosted cache steps): a real
directory, MATERIALIZED from the store by copy. It is not a link, because the
hosted job caches and archives those directories with tar, which would store a
link and not the oracle. `target/zenohd-build/zenoh-src`, the source tree the
census and the citation gate read, is materialized from the store's clone the
same way.

## Invariants this module holds

* Only an oracle that answers with the pin is published. The answer is
  `oracle_pin_gate.inspect`'s, the same classification the gate grades with,
  so the store cannot hold what the gate would call STALE. A product is
  published by renaming a complete staging directory, so a reader sees a whole
  product or none.
* Materializing never builds and never reaches the network. It replaces each
  file with `os.replace`, so a process already running an oracle keeps the
  inode it opened, and it writes the key file last, so an interrupted copy is
  not taken for a current one.
* The population is `ensure_zenohd_at_pin.resolve`'s, which is itself asserted
  equal to `oracle_pin_gate.population`: one set of oracles in all three.

Building stays in `build-zenohd.sh`, under a lock per version
(`<store>/zenohd/<version>/.lock`), because the build is what has to be
serialized: two slots asking for the same oracle at once build it once.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shlex
import shutil
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ensure_zenohd_at_pin as ensure  # noqa: E402
import oracle_pin_gate as g  # noqa: E402

ROOT = g.ROOT
#: Written into every product and every materialized directory, last.
KEY_FILE = ".oracle-key"
#: The materialized source view the census and the citation gate read.
SOURCE_VIEW = "target/zenohd-build/zenoh-src"
#: A product of another recipe that no checkout has materialized for this long
#: is removed when a newer one is published. A checkout on an older commit that
#: still wants it rebuilds it; nothing reads a product it did not ask for.
STALE_PRODUCT_DAYS = 14
#: A staging directory older than this was left by a build that died.
ORPHAN_STAGING_SECONDS = 24 * 3600

#: Exit code of `materialize` for a named oracle the store does not hold.
NOT_IN_STORE = 3


def store_root(env: dict[str, str] | None = None) -> pathlib.Path:
    env = os.environ if env is None else env
    explicit = env.get("WZ_ORACLE_STORE")
    if explicit:
        return pathlib.Path(explicit)
    cache = env.get("XDG_CACHE_HOME") or str(pathlib.Path(env.get("HOME", "~")) / ".cache")
    return pathlib.Path(cache).expanduser() / "watching-zenoh" / "oracles"


def recipe(script_text: str) -> str:
    return hashlib.sha256(script_text.encode("utf-8")).hexdigest()[:16]


class Layout:
    """Every path of one version's store, derived in one place."""

    def __init__(self, store: pathlib.Path, version: str, recipe_id: str):
        self.version = version
        self.recipe = recipe_id
        self.base = store / "zenohd" / version

    @property
    def lock(self) -> pathlib.Path:
        return self.base / ".lock"

    @property
    def source(self) -> pathlib.Path:
        return self.base / "src"

    def build(self, oracle: str) -> pathlib.Path:
        return self.base / "build" / pathlib.PurePosixPath(oracle).name

    @property
    def products(self) -> pathlib.Path:
        return self.base / "products"

    def product(self, oracle: str) -> pathlib.Path:
        return self.products / f"{pathlib.PurePosixPath(oracle).name}-{self.recipe}"

    def key(self, oracle: str) -> str:
        return f"{self.version} {pathlib.PurePosixPath(oracle).name} {self.recipe}\n"

    def source_key(self) -> str:
        return f"{self.version} src\n"


def layout_of_tree(env: dict[str, str] | None = None) -> tuple[Layout, list[str]]:
    """The layout `build-zenohd.sh` builds into: its `${ZENOHD_VERSION:-<pin>}`, read the same way."""
    env = os.environ if env is None else env
    script_text = g.BUILD_SCRIPT.read_text(encoding="utf-8")
    oracles = list(ensure.resolve(script_text))
    version = env.get("ZENOHD_VERSION") or g.pin(script_text)
    return Layout(store_root(env), version, recipe(script_text)), oracles


def source_dir(version: str, env: dict[str, str] | None = None) -> pathlib.Path:
    """The store's clone of `version`, for the readers of the source tree."""
    return store_root(env) / "zenohd" / version / "src"


def _read(path: pathlib.Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _files(directory: pathlib.Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.is_file() and p.name != KEY_FILE)


def _same_file(a: pathlib.Path, b: pathlib.Path) -> bool:
    """Size and modification time: `copy2` carries both, and a write in place moves the second."""
    sa, sb = a.stat(), b.stat()
    return sa.st_size == sb.st_size and sa.st_mtime_ns == sb.st_mtime_ns


def _replace_file(src: pathlib.Path, dest_dir: pathlib.Path, name: str) -> None:
    tmp = dest_dir / f".{name}.materializing.{os.getpid()}"
    shutil.copy2(src, tmp)
    os.replace(tmp, dest_dir / name)


def _write_key(directory: pathlib.Path, key: str) -> None:
    tmp = directory / f"{KEY_FILE}.{os.getpid()}"
    tmp.write_text(key, encoding="utf-8")
    os.replace(tmp, directory / KEY_FILE)


def materialize_oracle(root: pathlib.Path, layout: Layout, oracle: str) -> str:
    """Make `root/oracle` the store's product. Returns CURRENT, COPIED or ABSENT."""
    product = layout.product(oracle)
    key = layout.key(oracle)
    if _read(product / KEY_FILE) != key:
        return "ABSENT"
    target = root / oracle
    wanted = _files(product)
    if (
        _read(target / KEY_FILE) == key
        and target.is_dir()
        and _files(target) == wanted
        and all(_same_file(product / n, target / n) for n in wanted)
    ):
        os.utime(product / KEY_FILE)
        return "CURRENT"
    target.mkdir(parents=True, exist_ok=True)
    # The old key goes first: a copy that stops halfway must not read as current.
    (target / KEY_FILE).unlink(missing_ok=True)
    for name in wanted:
        _replace_file(product / name, target, name)
    for stale in set(_files(target)) - set(wanted):
        (target / stale).unlink()
    _write_key(target, key)
    os.utime(product / KEY_FILE)
    return "COPIED"


def materialize_source(root: pathlib.Path, layout: Layout) -> str:
    """Make `root/SOURCE_VIEW` the store's clone. Returns CURRENT, COPIED or ABSENT."""
    if _read(layout.source / KEY_FILE) != layout.source_key():
        return "ABSENT"
    view = root / SOURCE_VIEW
    if _read(view / KEY_FILE) == layout.source_key():
        return "CURRENT"
    view.parent.mkdir(parents=True, exist_ok=True)
    staging = pathlib.Path(tempfile.mkdtemp(prefix=".zenoh-src.", dir=view.parent))
    tree = staging / "tree"
    shutil.copytree(layout.source, tree, symlinks=True)
    retired = view.parent / f".zenoh-src.retired.{os.getpid()}"
    if view.exists():
        os.replace(view, retired)
    os.replace(tree, view)
    shutil.rmtree(retired, ignore_errors=True)
    shutil.rmtree(staging, ignore_errors=True)
    return "COPIED"


def seal_source(layout: Layout) -> None:
    """Mark the store's clone complete. Called by the build, under its lock."""
    _write_key(layout.source, layout.source_key())


def publish(layout: Layout, oracle: str, staging: pathlib.Path) -> str:
    """Move a complete staging directory into the store, if it answers at the pin.

    Returns "" on success, else the reason it was refused. Called under the
    build's lock, so no second publisher races this one.
    """
    finding = g.inspect(staging.parent, staging.name, layout.version)
    if finding.verdict != g.MATCH:
        return f"{finding.verdict}: {finding.detail}"
    _write_key(staging, layout.key(oracle))
    product = layout.product(oracle)
    if product.exists():
        retired = layout.products / f".retired.{product.name}.{os.getpid()}"
        os.replace(product, retired)
        shutil.rmtree(retired, ignore_errors=True)
    os.replace(staging, product)
    prune(layout, oracle)
    return ""


def prune(layout: Layout, oracle: str, now: float | None = None) -> list[str]:
    """Remove the products of other recipes nobody materialized lately, and dead staging."""
    now = time.time() if now is None else now
    name = pathlib.PurePosixPath(oracle).name
    removed: list[str] = []
    if not layout.products.is_dir():
        return removed
    current = layout.product(oracle).name
    for entry in layout.products.iterdir():
        if entry.name.startswith(".staging."):
            if now - entry.stat().st_mtime > ORPHAN_STAGING_SECONDS:
                shutil.rmtree(entry, ignore_errors=True)
                removed.append(entry.name)
            continue
        if entry.name == current or not entry.name.startswith(f"{name}-"):
            continue
        # `<name>-<16 hex>` only: `zenohd-` also prefixes `zenohd-shm-<recipe>`.
        if len(entry.name) != len(current):
            continue
        stamp = entry / KEY_FILE
        last = stamp.stat().st_mtime if stamp.exists() else entry.stat().st_mtime
        if now - last > STALE_PRODUCT_DAYS * 86400:
            shutil.rmtree(entry, ignore_errors=True)
            removed.append(entry.name)
    return removed


def staging_dir(layout: Layout, oracle: str) -> pathlib.Path:
    layout.products.mkdir(parents=True, exist_ok=True)
    name = pathlib.PurePosixPath(oracle).name
    return pathlib.Path(tempfile.mkdtemp(prefix=f".staging.{name}.", dir=layout.products))


def selftest() -> int:
    failures: list[str] = []
    checks = 0

    def expect(ok: bool, what: str) -> None:
        nonlocal checks
        checks += 1
        if not ok:
            failures.append(what)

    with tempfile.TemporaryDirectory() as td:
        base = pathlib.Path(td)
        store = base / "store"
        root = base / "tree"
        layout = Layout(store, "9.9.9", "0123456789abcdef")

        # The store root is the environment's, in order, and never the tree's.
        expect(
            store_root({"WZ_ORACLE_STORE": "/s", "XDG_CACHE_HOME": "/x"}) == pathlib.Path("/s"),
            "WZ_ORACLE_STORE did not win",
        )
        expect(
            store_root({"XDG_CACHE_HOME": "/x", "HOME": "/h"})
            == pathlib.Path("/x/watching-zenoh/oracles"),
            "XDG_CACHE_HOME was not used",
        )
        expect(
            store_root({"HOME": "/h"}) == pathlib.Path("/h/.cache/watching-zenoh/oracles"),
            "the HOME fallback is wrong",
        )

        def stage(answer: str) -> pathlib.Path:
            s = staging_dir(layout, "target/zenohd")
            b = s / "zenohd"
            b.write_text(f'#!/bin/sh\necho "{answer}"\n')
            b.chmod(0o755)
            (s / "plugin.so").write_text("so")
            return s

        target = "target/zenohd"
        # Nothing is materialized from an empty store.
        expect(
            materialize_oracle(root, layout, target) == "ABSENT",
            "an empty store materialized something",
        )

        # An oracle off the pin is refused and the store stays empty.
        off = stage("zenohd v1211779c built with rustc 1.97.1")
        expect(
            publish(layout, target, off).startswith(g.STALE), "a STALE oracle was published"
        )
        expect(not layout.product(target).exists(), "a refused oracle reached the store")
        shutil.rmtree(off)

        # An oracle at the pin is published, then materialized, then current.
        good = stage("zenohd v9.9.9 built with rustc 1.97.1")
        expect(publish(layout, target, good) == "", "an oracle at the pin was refused")
        expect(not good.exists(), "publishing left its staging directory behind")
        expect(
            materialize_oracle(root, layout, target) == "COPIED",
            "a published oracle was not copied",
        )
        expect(
            g.inspect(root, target, "9.9.9").verdict == g.MATCH,
            "the materialized oracle does not answer at the pin",
        )
        expect(
            materialize_oracle(root, layout, target) == "CURRENT",
            "a second materialize copied again",
        )

        # A file the product no longer has is removed; a file written in place,
        # at the same size, is restored.
        (root / target / "left-over").write_text("old")
        expect(
            materialize_oracle(root, layout, target) == "COPIED",
            "an extra file did not trigger a copy",
        )
        expect(
            not (root / target / "left-over").exists(),
            "a file the product does not have survived",
        )
        damaged = root / target / "plugin.so"
        damaged.write_text("SO")
        os.utime(damaged, ns=(damaged.stat().st_atime_ns, damaged.stat().st_mtime_ns + 10**9))
        expect(
            materialize_oracle(root, layout, target) == "COPIED",
            "a file written in place at the same size was taken for current",
        )
        expect(damaged.read_text() == "so", "a damaged file was not restored")

        # Another recipe is another key: the materialized copy is not current for it.
        other = Layout(store, "9.9.9", "fedcba9876543210")
        expect(
            materialize_oracle(root, other, target) == "ABSENT",
            "a product of another recipe was taken for this one",
        )

        # Pruning: an old product of another recipe goes, the current one and a
        # sibling oracle's whose name shares the prefix stay.
        stale = layout.products / "zenohd-fedcba9876543210"
        stale.mkdir()
        (stale / KEY_FILE).write_text(other.key(target))
        sibling = layout.products / "zenohd-shm-0123456789abcdef"
        sibling.mkdir()
        old = time.time() - (STALE_PRODUCT_DAYS + 1) * 86400
        for p in (stale / KEY_FILE, stale, sibling):
            os.utime(p, (old, old))
        removed = prune(layout, target)
        expect(removed == ["zenohd-fedcba9876543210"], f"prune removed {removed}")
        expect(
            layout.product(target).exists() and sibling.exists(),
            "prune removed the current product or a sibling oracle's",
        )

        # The source view: absent until sealed, copied once, then current.
        layout.source.mkdir(parents=True)
        (layout.source / "Cargo.toml").write_text("[workspace]\n")
        expect(materialize_source(root, layout) == "ABSENT", "an unsealed clone was materialized")
        seal_source(layout)
        expect(materialize_source(root, layout) == "COPIED", "a sealed clone was not materialized")
        expect(
            (root / SOURCE_VIEW / "Cargo.toml").is_file(), "the source view lacks the clone's files"
        )
        expect(
            materialize_source(root, layout) == "CURRENT", "a current source view was copied again"
        )

    for f in failures:
        print(f"oracle-store: selftest FAIL: {f}")
    if failures:
        return 1
    print(f"oracle-store: selftest OK ({checks} properties driven)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="oracle_store.py",
        description="The machine's store of built zenohd oracles (see the module docstring).",
    )
    sub = ap.add_subparsers(dest="command")
    sub.add_parser("selftest", help="drive the store against a temporary one")
    sub.add_parser("check", help="derive the layout of this tree and print it; reads no binary")
    p_paths = sub.add_parser("paths", help="shell assignments of one oracle's store paths")
    p_paths.add_argument("oracle")
    p_stage = sub.add_parser("stage", help="create and print a staging directory for one oracle")
    p_stage.add_argument("oracle")
    p_pub = sub.add_parser("publish", help="publish a staging directory (under the build's lock)")
    p_pub.add_argument("oracle")
    p_pub.add_argument("staging")
    sub.add_parser("seal-source", help="mark the store's clone complete (under the build's lock)")
    p_mat = sub.add_parser("materialize", help="copy what the store holds into target/; never builds")
    p_mat.add_argument("oracles", nargs="*", help="oracle dirs; all of them when none is named")
    args = ap.parse_args()

    if args.command == "selftest":
        return selftest()

    layout, oracles = layout_of_tree()

    if args.command == "check":
        print(
            f"  oracle-store: pin {layout.version}, recipe {layout.recipe}, "
            f"{len(oracles)} oracle(s); store {store_root()}"
        )
        for oracle in oracles:
            print(f"    {oracle:<24} -> products/{layout.product(oracle).name}")
        return 0

    def known(oracle: str) -> str:
        if oracle not in oracles:
            raise SystemExit(
                f"oracle-store: FAIL -- {oracle} is not an oracle this tree builds; "
                f"known: {', '.join(oracles)}"
            )
        return oracle

    if args.command == "paths":
        oracle = known(args.oracle)
        for name, value in (
            ("STORE_LOCK", layout.lock),
            ("STORE_SRC", layout.source),
            ("STORE_BUILD", layout.build(oracle)),
            ("STORE_PRODUCT", layout.product(oracle)),
        ):
            print(f"{name}={shlex.quote(str(value))}")
        return 0

    if args.command == "stage":
        print(staging_dir(layout, known(args.oracle)))
        return 0

    if args.command == "publish":
        refused = publish(layout, known(args.oracle), pathlib.Path(args.staging))
        if refused:
            print(
                f"oracle-store: REFUSED {args.oracle} -- {refused}; the store keeps "
                "only an oracle that answers with the pin",
                file=sys.stderr,
            )
            return 1
        print(f"oracle-store: PUBLISHED {args.oracle} -> {layout.product(args.oracle)}")
        return 0

    if args.command == "seal-source":
        seal_source(layout)
        return 0

    if args.command == "materialize":
        named = [known(o) for o in args.oracles]
        rc = 0
        for oracle in named or oracles:
            state = materialize_oracle(ROOT, layout, oracle)
            print(f"  oracle-store: {state:<8} {oracle}")
            if named and state == "ABSENT":
                rc = NOT_IN_STORE
        print(f"  oracle-store: {materialize_source(ROOT, layout):<8} {SOURCE_VIEW}")
        return rc

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
