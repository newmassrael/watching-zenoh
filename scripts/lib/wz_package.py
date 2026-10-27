#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3521 (no register item) -- the entry of `docs/target-build-contract.md`: build for a platform,
describe what was built.

    wz_package.py --platform ID --artifact ID... --out DIR [--cargo-profile release|debug]
                  [--profile ID] [--node ID | --node-file PATH]
    wz_package.py --verify DIR
    wz_package.py --sdk-bundle-check ID
    wz_package.py --write-fixtures | --check-fixtures | --record-measured DIR
    wz_package.py --selftest

`package` (the default) builds the named artifacts for the platform with cargo, copies each into
`DIR/lib` or `DIR/bin`, measures every file from its own bytes (`elf_facts`) and writes
`DIR/wz-target-manifest.json`: the one file a deployment tool reads. `--verify` is the gate on it:
it re-measures every artifact the manifest names and compares, so a manifest that no longer says
what the files are is a finding.

## Fixtures (step 7)

`deploy/fixtures/manifests/` is a conformance corpus a consumer's reader and `--verify` are both held
to: synthetic packages made here (valid ones, and each with one defect, at the level a reader sees it:
`shape`, `manifest` or `files`), measured manifests of real builds, and an `index.json` of verdicts.
`--check-fixtures` (in the selftest) holds the corpus to what the entry makes now.

## Bundling (T5)

A NEEDED is `system` when the platform row assumes every device of its kind has it, and `bundled`
when the row lists it in `bundle_from_sdk`: the SDK ships it for applications to carry and a device
may lack it. The entry then copies the file the platform's linker finds into `DIR/lib/<SONAME>`,
measures it, and does the same for what it needs in turn, so the package's closure is closed. The
manifest's `bundled` lists each with its own measurements, and the artifact's NEEDED entry names the
file. `--sdk-bundle-check ID` reads every library a row bundles from the SDK in the environment,
whether or not an artifact needs it today (Layer C1sp runs it where the SDK is).

## What it refuses, and why that is an exit and not a warning (T10)

A refusal writes NO manifest and removes the directory it made: a tool that reads a half-described
artifact would ship it. It refuses a platform it has no statement for (a platform that does not
state `os_provides` and `system_assumed` is unassessed), a missing toolchain variable (named, so
the caller sees which), a build whose capabilities ask for a facility the platform does not give
(naming the capability), a NEEDED nobody assumed and nothing bundles (naming the library), a
library to bundle that the SDK does not have or that is another library than its name says, and a
stamp whose family is not the artifact's.

## A node declaration as an input

An artifact whose row says `input = "node"` is built from a node declaration
(`docs/target-build-contract.md` 5b): a registered one (`deploy/nodes/ID.toml`) named with `--node
ID`, whose tracked generated constants must be current, or a file a consumer wrote, given with
`--node-file PATH` and generated into the build's own directory. Both are validated the same way
before anything is built. The build takes the declaration's features and budgets, and the file's
facts note carries the node's id and the digest of the declaration. The package carries the
declaration itself (`node/<id>.toml`, the manifest's `inputs`), and `--verify` resolves it from those
bytes and holds the node file to it with no tree consulted: a node is identified by the digest of what
it was built from, so a file built from another declaration is a finding. The artifact row states the
operating systems its port exists for (`os`), and a platform outside them is refused by name.

## What it does not do

A registered profile builds the libraries only: it resolves to an ABI's features, which an
executable has no mapping for. A native build (the platform's triple is the compiler's host) is built without
`--target`, so it shares the workspace's own build directory; a cross build passes it.

Exit 0 on success, 2 on a refusal, 1 on a failed `--verify` or a failure of the entry itself.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import elf_facts  # noqa: E402
import wz_config  # noqa: E402
import wz_node  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST_NAME = "wz-target-manifest.json"
# `bundled` (the libraries copied from the SDK, T5) was added within schema 1: an added key changes
# the meaning of none, and a reader ignores a key it does not know (T7).
MANIFEST_SCHEMA = 1

TOP_KEYS = ["schema", "catalog_version", "built_from", "platform", "profile", "toolchain", "system_assumed",
            "bundled", "inputs", "artifacts"]
BUNDLED_KEYS = ["soname", "path", "sha256", "size", "elf"]
# An input the package carries beside what was built from it: a node declaration, under `node/`, so
# the package says what it was made from in bytes a reader can hold the built file to with no tree.
INPUT_KEYS = ["kind", "id", "path", "sha256", "size"]
PROFILE_KEYS = ["id", "base", "capabilities", "limits"]
PROFILES_DIR = ROOT / "configs" / "profiles"
BUILT_FROM_KEYS = ["commit", "tree_clean"]
PLATFORM_KEYS = ["id", "triple", "os", "libc", "network_stack", "support", "strongest_green_lane"]
TOOLCHAIN_KEYS = ["rustc", "cc", "sdk"]
ARTIFACT_KEYS = ["id", "name", "kind", "path", "sha256", "size", "elf", "abi", "provides", "features",
                 "resolved_features", "device_requires", "requires", "may_require", "unassessed_features"]
# What an entry wrote before `requires` and `may_require` were added within schema 1 (T9): the same
# keys without the two, a bound that is not split. A reader takes the whole of such a
# `device_requires` as what a run may ask; the manifests recorded from builds before the split are
# of this form, and an entry writes the other.
UNSPLIT_ARTIFACT_KEYS = [k for k in ARTIFACT_KEYS if k not in ("requires", "may_require")]
ELF_KEYS = ["class", "machine", "linking", "interpreter", "soname", "runpath", "rpath", "needed", "os_floor"]
FLOOR_KEYS = ["glibc", "android_api_note", "symbol_version_tags"]


class Refusal(Exception):
    """The entry will not describe this build."""


# ---------------------------------------------------------------------------
# What a built file is, from its bytes and the declaration
# ---------------------------------------------------------------------------


def declaration_path(node_id: str) -> str:
    """Where a node declaration lies in the package: under `node`, by the node's id, which is the
    name the declaration's own `[node] id` must match."""
    return f"node/{node_id}.toml"


def input_entry(view: dict) -> dict:
    """The manifest's entry for the declaration a node was built from, from the bytes the build read."""
    return {"kind": "node-declaration", "id": view["id"], "path": declaration_path(view["id"]),
            "sha256": view["declaration_sha256"], "size": len(view["source"])}


def bundled_path(soname: str) -> str:
    """Where a bundled library lies in the package: under `lib`, by its SONAME, which is the name the
    loader looks for."""
    return f"lib/{soname}"


def classify_needed(needed: list[str], platform: dict, who: str) -> list[dict]:
    """Every NEEDED as `system` (assumed by the platform row), `bundled` (a library the row bundles
    from the SDK, named by the file it becomes in the package), or a refusal naming the library."""
    out = []
    for soname in needed:
        if soname in platform["system_assumed"]:
            out.append({"soname": soname, "provided_by": "system"})
        elif soname in platform.get("bundle_from_sdk", []):
            out.append({"soname": soname, "provided_by": "bundled", "artifact": bundled_path(soname)})
        else:
            raise Refusal(f"{who} needs {soname}, which the platform does not assume and nothing bundles: "
                          "name it in the platform's system_assumed (every device of the kind has it) or "
                          "bundle_from_sdk (the SDK ships it and a device may lack it)")
    return out


def elf_object(measured: dict, platform: dict, who: str) -> dict:
    return {
        "class": measured["class"],
        "machine": measured["machine"],
        "linking": measured["linking"],
        "interpreter": measured["interpreter"],
        "soname": measured["soname"],
        "runpath": measured["runpath"],
        "rpath": measured["rpath"],
        "needed": classify_needed(measured["needed"], platform, who),
        "os_floor": {
            "glibc": measured["glibc_floor"],
            "android_api_note": measured["android_api_note"],
            "symbol_version_tags": measured["symbol_version_tags"],
        },
    }


def provides_of(decl: dict, row: dict, features: list[str], measured: dict) -> list[dict]:
    """The roles a built artifact provides: a role whose feature is off is absent."""
    out = []
    for role in decl["roles"]:
        if role["artifact"] != row["id"]:
            continue
        need = role.get("needs_feature")
        if need is not None and need not in features:
            continue
        entry: dict = {"role": role["id"]}
        via = {}
        for key, name in (("via_argument", "argument"), ("via_kind", "kind"), ("via_key", "key")):
            if key in role:
                via[name] = role[key]
        if via:
            entry["via"] = via
        for name in ([role["facts_list"]] if "facts_list" in role else role.get("facts_lists", [])):
            lists = measured["facts"]
            if lists is None or name not in lists:
                raise Refusal(f"{row['id']} provides {role['id']} but its file has no facts list "
                              f"`{name}`: it was not built with the facts note")
            entry[name] = lists[name]
        out.append(entry)
    return out


def executable_requires(decl: dict, platform: dict, row: dict,
                        resolved: dict[str, list[str]]) -> tuple[list[str] | None, list[str]]:
    """An executable's facilities from its assessed packages and the features cargo resolved for it.

    `None` is UNKNOWN (an enabled feature nobody assessed), with those features named beside it.
    A facility the platform lacks is a refusal naming the packages and features that ask for it.
    """
    needs, unassessed = wz_config.resolve_package_needs(decl, resolved, row["package"])
    provided = set(platform["os_provides"])
    rows = {(r["package"], r["feature"]): set(r["os_needs"]) for r in decl["package_features"]}
    present = {p["package"]: set(p["os_needs"]) for p in decl["assessed_packages"]
               if p["package"] in resolved or p["package"] == row["package"]}
    for facility in sorted(set(decl["os_base"]) | {f for s in rows.values() for f in s}
                           | {f for s in present.values() for f in s}):
        if facility in provided:
            continue
        asking = [p for p, s in sorted(present.items()) if facility in s]
        asking += [f"{p}/{f}" for (p, f), s in sorted(rows.items())
                   if facility in s and f in resolved.get(p, [])]
        if facility in decl["os_base"]:
            asking.insert(0, "base")
        if asking:
            raise Refusal(f"{row['id']} may ask for {facility}, which platform {platform['id']} does not "
                          f"provide (asked by {', '.join(asking)})")
    return needs, unassessed


def device_requires(decl: dict, platform: dict, row: dict, features: list[str]) -> list[str] | None:
    """The facilities a library's capabilities may ask for. A facility the platform lacks is a
    refusal naming the capability. (An executable's come from `executable_requires`.)"""
    on = {f for f in features if f in decl["caps"]}
    gaps = wz_config.platform_gaps(decl, platform["id"], on)
    if gaps:
        why = "; ".join(f"{facility} (asked by {', '.join(who)})" for facility, who in sorted(gaps.items()))
        raise Refusal(f"{row['id']} may ask for facilities platform {platform['id']} does not provide: {why}")
    return sorted(wz_config.os_needs_of(decl, on))


def node_of_file(row: dict, measured: dict, features: list[str], declarations: dict[str, dict]) -> dict:
    """The declaration a node-built executable says it was built from, among those the caller holds.

    The file's facts note carries the node's id and the digest of the declaration it was generated
    from. A declaration is identified by that digest, not by a name: `declarations` maps a digest to
    the resolved declaration (the build's own input when packaging, the copy the package carries when
    verifying), so a file built from any other declaration describes a node the package does not
    declare. The id must be that declaration's, and the features the build used the ones it asks for.
    """
    lists = measured["facts"] or {}
    for name in ("node_id", "declaration_sha256"):
        if len(lists.get(name, [])) != 1:
            raise Refusal(f"{row['id']} is built from a node declaration and its facts note has no single "
                          f"`{name}`: it was not built by this entry")
    node_id, built = lists["node_id"][0], lists["declaration_sha256"][0]
    view = declarations.get(built)
    if view is None:
        raise Refusal(f"{row['id']} was built from declaration {built[:12]} of `{node_id}`, and the package "
                      "carries no declaration with that digest: the file describes a node nobody declares")
    if view["id"] != node_id:
        raise Refusal(f"{row['id']} says it is the node `{node_id}`, and declaration {built[:12]} is the "
                      f"node `{view['id']}`")
    # Cargo lists the package's `default` feature among those it enabled, whatever it contains.
    chosen = sorted(set(features) - {"default"})
    if chosen != sorted(view["features"]):
        raise Refusal(f"{row['id']} was built with the features {chosen}, the declaration of "
                      f"`{node_id}` asks for {sorted(view['features'])}")
    return view


def node_requires(platform: dict, row: dict, node: dict) -> tuple[list[str], list[str]]:
    """What a node asks of a device, on every run and on some: its target's own needs and the
    sockets its endpoints' schemes use, and what a group may list (`wz_node.view_of`). A facility
    the platform lacks is a refusal naming the node."""
    asked = sorted(set(node["requires"]) | set(node["may_require"]))
    lacking = [f for f in asked if f not in platform["os_provides"]]
    if lacking:
        raise Refusal(f"{row['id']} (the node `{node['id']}`) asks for {', '.join(lacking)}, which platform "
                      f"{platform['id']} does not provide")
    return node["requires"], node["may_require"]


def split_requires(decl: dict, upper: list[str] | None) -> tuple[list[str], list[str] | None]:
    """A host build's facilities as `requires` (the `[os] always` every run asks for and cannot go
    on without) and `may_require` (the rest of the upper bound `upper`, `None` when it is UNKNOWN).

    `requires` is known whatever is unassessed: an unassessed feature can only add to what a run
    may ask, and `always` is asked by the runtime before any feature is reached.
    """
    requires = sorted(decl["os_always"])
    return requires, (None if upper is None else sorted(set(upper) - set(requires)))


def requires_findings(where: str, art: dict) -> list[str]:
    """What breaks the three lists' invariant (T9): `requires` is a list, `may_require` a list
    disjoint from it or `None`, `device_requires` their union or `None` exactly with
    `may_require`, and `unassessed_features` non-empty exactly when they are `None`."""
    req, may, union, unassessed = (art["requires"], art["may_require"], art["device_requires"],
                                   art["unassessed_features"])
    if not isinstance(req, list) or req != sorted(set(req)):
        return [f"{where}: requires is not a sorted list of distinct facilities"]
    if may is None or union is None:
        if may is not None or union is not None:
            return [f"{where}: one of may_require and device_requires is null and the other is not"]
        if not unassessed:
            return [f"{where}: may_require is unknown and no unassessed feature says why"]
        return []
    out = []
    if not isinstance(may, list) or may != sorted(set(may)):
        out.append(f"{where}: may_require is not a sorted list of distinct facilities")
    elif set(req) & set(may):
        out.append(f"{where}: {sorted(set(req) & set(may))} are in both requires and may_require")
    elif union != sorted(set(req) | set(may)):
        out.append(f"{where}: device_requires {union} is not requires and may_require together")
    if unassessed:
        out.append(f"{where}: device_requires is known and unassessed_features is not empty")
    return out


def artifact_entry(decl: dict, platform: dict, row: dict, relpath: str, blob: bytes, features: list[str],
                   resolved: dict[str, list[str]] | None = None,
                   declarations: dict[str, dict] | None = None) -> dict:
    """The manifest's entry for one built file, from its bytes: the same call serves `package`
    (which writes it) and `--verify` (which compares it).

    `resolved` is the features cargo enabled in each package of the build (a build fact, recorded
    in the manifest for the assessed packages only, so a re-measurement can recompute from it).
    `declarations` are the node declarations the package carries, by digest (`node_of_file`).
    """
    measured = elf_facts.describe(blob)
    stamp = measured["abi_stamp"]
    if stamp["family"] != row["family"]:
        raise Refusal(f"{row['id']}'s stamp says family {stamp['family']!r}, not {row['family']!r}")
    features = sorted(features)
    kept = {p["package"]: sorted(set(resolved[p["package"]])) for p in decl["assessed_packages"]
            if p["package"] in (resolved or {})}
    if row.get("input") == "node":
        node = node_of_file(row, measured, features, declarations or {})
        required, may, unassessed = *node_requires(platform, row, node), []
    else:
        if row["kind"] == "executable":
            upper, unassessed = executable_requires(decl, platform, row, kept)
        else:
            upper, unassessed = device_requires(decl, platform, row, features), []
        required, may = split_requires(decl, upper)
    union = None if may is None else sorted(set(required) | set(may))
    return {
        "id": row["id"],
        "name": pathlib.PurePosixPath(relpath).name,
        "kind": row["kind"],
        "path": relpath,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "size": len(blob),
        "elf": elf_object(measured, platform, row["id"]),
        "abi": {"family": stamp["family"], "revision": stamp["revision"], "layout": stamp["layout"]},
        "provides": provides_of(decl, row, features, measured),
        "features": features,
        "resolved_features": kept,
        "device_requires": union,
        "requires": required,
        "may_require": may,
        "unassessed_features": unassessed,
    }


def bundled_entry(platform: dict, soname: str, blob: bytes) -> dict:
    """The manifest's entry for one library the package carries from the SDK, from its bytes: the
    same call serves `bundle` (which writes it) and `--verify` (which compares it). The file must be
    the library the NEEDED names (its own SONAME), one the platform bundles, and its own NEEDED are
    classified like an artifact's, so the closure of the package is closed or refused."""
    who = f"the bundled {soname}"
    if soname not in platform.get("bundle_from_sdk", []):
        raise Refusal(f"{who} is not a library platform {platform['id']} bundles from its SDK")
    measured = elf_facts.linkage_facts(blob)
    if measured["soname"] != soname:
        raise Refusal(f"{who}: the SDK's file says SONAME {measured['soname']!r}, so it is not the library "
                      "the NEEDED names")
    return {
        "soname": soname,
        "path": bundled_path(soname),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "size": len(blob),
        "elf": elf_object(measured, platform, who),
    }


def bundle(platform: dict, entries: list[dict], out: pathlib.Path, locate=None) -> list[dict]:
    """Copy into `out/lib` every library the package needs from the SDK, and what those need in turn,
    and describe each; in SONAME order, so the same inputs give the same manifest.

    `locate` finds a SONAME's file in the SDK (`sdk_library`, the search the platform's linker does);
    a library the SDK does not have is a refusal naming it, since a package that says `bundled` for a
    file it does not hold is a closure that is not closed.
    """
    locate = locate or sdk_library
    wanted = [n["soname"] for e in entries for n in e["elf"]["needed"] if n["provided_by"] == "bundled"]
    done: dict[str, dict] = {}
    while wanted:
        soname = wanted.pop(0)
        if soname in done:
            continue
        found = locate(platform, soname)
        if found is None:
            raise Refusal(f"{soname} is to be bundled for platform {platform['id']} and the SDK's linker does "
                          "not find it")
        dest = out / bundled_path(soname)
        if dest.exists():
            raise Refusal(f"{soname} is to be bundled and an artifact of the package has that file name")
        dest.parent.mkdir(exist_ok=True)
        # The bytes only: the SDK's own mode (often read-only) is not a property of the library.
        shutil.copyfile(found, dest)
        entry = bundled_entry(platform, soname, dest.read_bytes())
        done[soname] = entry
        wanted += [n["soname"] for n in entry["elf"]["needed"] if n["provided_by"] == "bundled"]
    return [done[name] for name in sorted(done)]


def preflight(decl: dict, platform_id: str, artifact_ids: list[str]) -> tuple[dict, list[dict]]:
    """The platform and the artifact rows, or the refusal that stops the build before it starts."""
    platform = next((p for p in decl["platforms"] if p["id"] == platform_id), None)
    if platform is None:
        raise Refusal(f"no platform `{platform_id}` is declared "
                      f"(known: {', '.join(p['id'] for p in decl['platforms'])})")
    for key in ("os_provides", "system_assumed"):
        if key not in platform:
            raise Refusal(f"platform {platform_id} is unassessed: it states no `{key}`, and the entry does "
                          "not guess what a device has")
    rows = []
    for aid in artifact_ids:
        row = next((a for a in decl["artifacts"] if a["id"] == aid), None)
        if row is None:
            raise Refusal(f"no artifact `{aid}` is declared "
                          f"(known: {', '.join(a['id'] for a in decl['artifacts'])})")
        if row.get("os") is not None and platform["os"] not in row["os"]:
            raise Refusal(f"artifact {aid} is not built for platform {platform_id} (operating system "
                          f"{platform['os']}): {row['os_note']}; it is built for {', '.join(row['os'])} only")
        rows.append(row)
    # Declaration order, whatever order the caller named them in: the manifest is reproducible.
    order = {a["id"]: i for i, a in enumerate(decl["artifacts"])}
    return platform, sorted(rows, key=lambda r: order[r["id"]])


def lane_plan(decl: dict, platform_id: str) -> tuple[list[str], list[str]]:
    """What Layer C1sp packages for a platform: the artifacts its operating system supports that need
    no declaration, and, when it supports the declared-node artifact, every registered node (a node
    artifact is made from one declaration, so each is a package call of its own). An artifact the
    platform's operating system is not in the `os` of is left out here and refused by `preflight`
    when named, so the lane asks for what the platform can have and never for a refusal."""
    platform = next((p for p in decl["platforms"] if p["id"] == platform_id), None)
    if platform is None:
        raise Refusal(f"no platform `{platform_id}` is declared "
                      f"(known: {', '.join(p['id'] for p in decl['platforms'])})")
    plain, with_nodes = [], False
    for row in decl["artifacts"]:
        if row.get("os") is not None and platform["os"] not in row["os"]:
            continue
        if row.get("input") == "node":
            with_nodes = True
        else:
            plain.append(row["id"])
    nodes = sorted(p.stem for p in wz_node.NODES.glob("*.toml")) if with_nodes else []
    return plain, nodes


# ---------------------------------------------------------------------------
# A registered profile as an input (docs/target-build-contract.md T13)
# ---------------------------------------------------------------------------


def resolve_profile(decl: dict, profile_id: str) -> dict:
    """What a registered profile (`configs/profiles/<id>.conf`) asks of a build: its base original,
    the capabilities that are on once the original's defaults and the profile are merged, and the
    limits it sets off their defaults. Resolved strictly by the pinned Kconfig interpreter (C9)."""
    if not wz_config.PLATFORM_ID_RE.match(profile_id):
        raise Refusal(f"`{profile_id}` is not the name of a registered profile")
    path = PROFILES_DIR / f"{profile_id}.conf"
    if not path.is_file():
        known = sorted(p.stem for p in PROFILES_DIR.glob("*.conf"))
        raise Refusal(f"no registered profile `{profile_id}` (known: {', '.join(known)}); the entry takes a "
                      "name, not a path, so a profile is a versioned contract and not a file anyone wrote")
    if wz_config.kconfiglib_module() is None:
        raise Refusal("a profile is resolved by the pinned Kconfig interpreter, which is not installed: "
                      "run scripts/provision-kconfiglib.sh")
    try:
        kconf = wz_config.resolve([path])
    except wz_config.PresetError as err:
        raise Refusal(f"profile {profile_id} does not resolve: {err}") from err
    limits = {}
    for line in wz_config.resolved_limit_env(decl, kconf):
        key, _, value = line.partition("=")
        limits[key] = int(value)
    return {
        "id": profile_id,
        "base": wz_config.preset_header(path.read_text(encoding="utf-8")).get("base"),
        "capabilities": sorted(wz_config.resolved_caps(decl, kconf)),
        "limits": dict(sorted(limits.items())),
    }


def profile_cargo_args(decl: dict, row: dict, view: dict) -> list[str]:
    """The cargo arguments a library artifact is built with under a profile: no default features
    and exactly the features the capability graph gives its ABI for the profile's capabilities."""
    if row["kind"] != "shared-library":
        raise Refusal(f"profile {view['id']} cannot apply to {row['id']}: a profile resolves to the "
                      "features of an ABI library, and an executable has no such mapping")
    return wz_config.cargo_args(decl, row["abi"], set(view["capabilities"])).split()


def profile_findings(decl: dict, view: dict, entries: list[dict]) -> list[str]:
    """What is wrong with the artifacts a profile built: a capability the profile turns on that a
    library lacks, or one it leaves off that the library has."""
    out = []
    on = set(view["capabilities"])
    for art in entries:
        row = next((a for a in decl["artifacts"] if a["id"] == art["id"]), None)
        if row is None or row["kind"] != "shared-library":
            out.append(f"artifact {art['id']!r}: a profile does not apply to it")
            continue
        abi = row["abi"]
        built = set(art["features"])
        want = set(wz_config.features_for(decl, abi, on))
        for feature in sorted(want - built):
            out.append(f"artifact {art['id']!r} lacks the feature `{feature}` profile {view['id']} asks for")
        closed = wz_config.closure(decl["caps"], on)
        for cid in sorted(c for c in built
                          if c in decl["caps"] and abi in decl["caps"][c]["abis"] and c not in closed):
            out.append(f"artifact {art['id']!r} has the capability `{cid}`, which profile {view['id']} leaves off")
    return out


def assemble(decl: dict, platform: dict, built_from: dict, toolchain: dict, entries: list[dict],
             profile: dict | None = None, bundled: list[dict] | None = None,
             inputs: list[dict] | None = None) -> dict:
    return {
        "schema": MANIFEST_SCHEMA,
        "catalog_version": decl["catalog_version"],
        "built_from": built_from,
        "platform": {
            "id": platform["id"],
            "triple": platform["triple"],
            "os": platform["os"],
            "libc": platform["libc"],
            "network_stack": platform.get("network_stack"),
            "support": platform["support"],
            "strongest_green_lane": platform["lane"],
        },
        "profile": profile,
        "toolchain": toolchain,
        "system_assumed": list(platform["system_assumed"]),
        "bundled": list(bundled or []),
        "inputs": sorted(inputs or [], key=lambda item: item["path"]),
        "artifacts": entries,
    }


def render(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# The gate: re-measure what a manifest describes
# ---------------------------------------------------------------------------


def shape_findings(manifest: object) -> list[str]:
    """The manifest's shape: the keys of schema 1, in order, none more."""
    if not isinstance(manifest, dict):
        return ["the manifest is not a JSON object"]
    out: list[str] = []

    def keys(where: str, obj: object, want: list[str]) -> bool:
        if not isinstance(obj, dict):
            out.append(f"{where} is not an object")
            return False
        if list(obj) != want:
            out.append(f"{where} has the keys {list(obj)}, schema {MANIFEST_SCHEMA} has {want}, in that order")
            return False
        return True

    if not keys("the manifest", manifest, TOP_KEYS):
        return out
    keys("built_from", manifest["built_from"], BUILT_FROM_KEYS)
    keys("platform", manifest["platform"], PLATFORM_KEYS)
    if manifest["profile"] is not None:
        keys("profile", manifest["profile"], PROFILE_KEYS)
    keys("toolchain", manifest["toolchain"], TOOLCHAIN_KEYS)
    if not isinstance(manifest["bundled"], list):
        out.append("bundled is not a list")
        return out
    for i, lib in enumerate(manifest["bundled"]):
        if keys(f"bundled[{i}]", lib, BUNDLED_KEYS):
            if keys(f"bundled[{i}].elf", lib["elf"], ELF_KEYS):
                keys(f"bundled[{i}].elf.os_floor", lib["elf"]["os_floor"], FLOOR_KEYS)
    if not isinstance(manifest["inputs"], list):
        out.append("inputs is not a list")
        return out
    for i, item in enumerate(manifest["inputs"]):
        keys(f"inputs[{i}]", item, INPUT_KEYS)
    if not isinstance(manifest["artifacts"], list) or not manifest["artifacts"]:
        out.append("artifacts is not a non-empty list")
        return out
    forms = set()
    for i, art in enumerate(manifest["artifacts"]):
        split = not isinstance(art, dict) or list(art) != UNSPLIT_ARTIFACT_KEYS
        forms.add(split)
        if keys(f"artifacts[{i}]", art, ARTIFACT_KEYS if split else UNSPLIT_ARTIFACT_KEYS):
            if keys(f"artifacts[{i}].elf", art["elf"], ELF_KEYS):
                keys(f"artifacts[{i}].elf.os_floor", art["elf"]["os_floor"], FLOOR_KEYS)
            if split:
                out.extend(requires_findings(f"artifacts[{i}]", art))
    if len(forms) > 1:
        out.append("the artifacts split the bound in one and not in another: one entry wrote the manifest")
    return out


def safe_relpath(path: str) -> bool:
    """A manifest path is a relative, `/`-separated string that stays inside the directory. It is
    judged as text (a manifest's path is not a place on this machine's filesystem), so no walked
    root's position can change the answer."""
    return bool(path) and not path.startswith("/") and ".." not in path.split("/") and "\\" not in path


def verify_dir(out: pathlib.Path, decl: dict, resolver=None) -> list[str]:
    """What is wrong with a packaged directory, from its files and the declaration.

    Every measured field is read again from the file and compared with the manifest, so a file
    replaced after packaging, a manifest edited by hand and a declaration that moved are each a
    finding, and a file the manifest does not mention is one too.
    """
    resolver = resolver or resolve_profile
    path = out / MANIFEST_NAME
    if not path.is_file():
        return [f"{path} is missing"]
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        return [f"{path} is not readable JSON: {err}"]
    out_findings = shape_findings(manifest)
    if out_findings:
        return out_findings
    findings: list[str] = []
    if manifest["schema"] != MANIFEST_SCHEMA:
        findings.append(f"schema is {manifest['schema']!r}, this gate reads {MANIFEST_SCHEMA}")
        return findings
    if manifest["catalog_version"] != decl["catalog_version"]:
        findings.append(f"catalog_version is {manifest['catalog_version']}, the declaration's is "
                        f"{decl['catalog_version']}")
    plat = manifest["platform"]
    row = next((p for p in decl["platforms"] if p["id"] == plat["id"]), None)
    if row is None:
        return findings + [f"the platform `{plat['id']}` is not declared"]
    want_platform = {"id": row["id"], "triple": row["triple"], "os": row["os"], "libc": row["libc"],
                     "network_stack": row.get("network_stack"), "support": row["support"],
                     "strongest_green_lane": row["lane"]}
    if plat != want_platform:
        findings.append(f"platform {plat} differs from its declaration {want_platform}")
    if "system_assumed" not in row or manifest["system_assumed"] != row["system_assumed"]:
        findings.append("system_assumed differs from the platform row's")
    sdk = manifest["toolchain"]["sdk"]
    if (sdk or {}).get("kind") != row.get("sdk_kind") and sdk is not None:
        findings.append(f"toolchain.sdk is a `{sdk.get('kind')}` and the platform row names "
                        f"`{row.get('sdk_kind')}`")
    sdk_keys = {"android-ndk": {"kind", "revision"}, "qnx-sdp": {"kind", "revision"},
                "yocto": {"kind", "revision", "target_arch", "target_os"}}
    if sdk is not None and set(sdk) != sdk_keys.get(sdk.get("kind"), set()):
        findings.append(f"toolchain.sdk has the keys {sorted(sdk)}, the entry writes "
                        f"{sorted(sdk_keys.get(sdk.get('kind'), set())) or 'a kind it knows'} for that kind")
    if "os_provides" not in row or "system_assumed" not in row:
        return findings + [f"platform {row['id']} is unassessed in the declaration"]
    listed = set()
    # The declarations the package carries, each re-measured and resolved from its own bytes (no tree
    # is consulted: a node is identified by the digest of what it was built from), so a node file is
    # held to the declaration beside it and a declaration nothing was built from is a finding.
    declarations: dict[str, dict] = {}
    paths = [item["path"] for item in manifest["inputs"]]
    if paths != sorted(set(paths)):
        findings.append(f"inputs is {paths}, not one entry per path in path order")
    with tempfile.TemporaryDirectory(prefix="wz-verify-node-") as work:
        for item in manifest["inputs"]:
            who = f"input {item['id']!r}"
            if item["kind"] != "node-declaration":
                findings.append(f"{who}: kind {item['kind']!r} is not an input this entry carries")
                continue
            if "/" in item["id"] or not safe_relpath(item["path"]) or item["path"] != declaration_path(item["id"]):
                findings.append(f"{who}: path {item['path']!r} is not node/ and the id, inside the directory")
                continue
            listed.add(item["path"])
            file = out / item["path"]
            if not file.is_file():
                findings.append(f"{who}: {item['path']} is missing")
                continue
            blob = file.read_bytes()
            measured = {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
            for key, value in measured.items():
                if item[key] != value:
                    findings.append(f"{who}: {key} is {item[key]!r} in the manifest and {value!r} read from "
                                    f"{item['path']} now")
            try:
                view = wz_node.resolve_file(file, decl, pathlib.Path(work))
            except (ValueError, OSError) as err:
                findings.append(f"{who}: {item['path']} does not resolve: {err}")
                continue
            declarations[view["declaration_sha256"]] = view
    built_from = {sha for art in manifest["artifacts"] for role in art.get("provides", [])
                  if isinstance(role, dict) for sha in role.get("declaration_sha256", [])}
    for item in manifest["inputs"]:
        if item.get("sha256") not in built_from:
            findings.append(f"input {item.get('id')!r}: the package carries it and nothing in it was built from it")
    for art in manifest["artifacts"]:
        who = f"artifact {art['id']!r}"
        arow = next((a for a in decl["artifacts"] if a["id"] == art["id"]), None)
        if arow is None:
            findings.append(f"{who} is not declared")
            continue
        if not safe_relpath(art["path"]):
            findings.append(f"{who}: path {art['path']!r} is not a relative path inside the directory")
            continue
        listed.add(art["path"])
        file = out / art["path"]
        if not file.is_file():
            findings.append(f"{who}: {art['path']} is missing")
            continue
        blob = file.read_bytes()
        try:
            again = artifact_entry(decl, row, arow, art["path"], blob, art["features"], art["resolved_features"],
                                   declarations)
        except (Refusal, elf_facts.ElfError) as err:
            findings.append(f"{who}: re-measuring {art['path']}: {err}")
            continue
        for key in (ARTIFACT_KEYS if "requires" in art else UNSPLIT_ARTIFACT_KEYS):
            if again[key] != art[key]:
                findings.append(f"{who}: {key} is {art[key]!r} in the manifest and {again[key]!r} "
                                f"read from {art['path']} now")
    # The libraries carried from the SDK: each re-measured like an artifact, and the set held to the
    # closure, so a bundled file nothing needs and a `bundled` NEEDED with no file are both findings.
    bundled = manifest["bundled"]
    names = [lib["soname"] for lib in bundled]
    if bundled and sdk is None:
        findings.append("libraries are bundled and the manifest names no SDK they were taken from")
    if names != sorted(set(names)):
        findings.append(f"bundled is {names}, not one entry per SONAME in SONAME order")
    for lib in bundled:
        who = f"bundled {lib['soname']!r}"
        if "/" in lib["soname"] or not safe_relpath(lib["path"]) or lib["path"] != bundled_path(lib["soname"]):
            findings.append(f"{who}: path {lib['path']!r} is not lib/ and the SONAME, inside the directory")
            continue
        listed.add(lib["path"])
        file = out / lib["path"]
        if not file.is_file():
            findings.append(f"{who}: {lib['path']} is missing")
            continue
        try:
            again = bundled_entry(row, lib["soname"], file.read_bytes())
        except (Refusal, elf_facts.ElfError) as err:
            findings.append(f"{who}: re-measuring {lib['path']}: {err}")
            continue
        for key in BUNDLED_KEYS:
            if again[key] != lib[key]:
                findings.append(f"{who}: {key} is {lib[key]!r} in the manifest and {again[key]!r} "
                                f"read from {lib['path']} now")
    asked = {n.get("soname") for item in [*manifest["artifacts"], *bundled]
             for n in item["elf"]["needed"] if isinstance(n, dict) and n.get("provided_by") == "bundled"}
    for name in sorted(asked - set(names)):
        findings.append(f"{name} is needed as bundled and the manifest bundles no {name}")
    for name in sorted(set(names) - asked):
        findings.append(f"{name} is bundled and nothing in the package needs it")
    profile = manifest["profile"]
    if profile is not None:
        # A profile is a registered contract, so it is resolved again from its file: a manifest that
        # names a profile the tree no longer resolves the same way, or artifacts that no longer
        # hold what the profile turns on and off, are findings.
        try:
            want = resolver(decl, profile["id"])
        except Refusal as err:
            findings.append(f"profile {profile['id']!r}: {err}")
        else:
            if profile != want:
                findings.append(f"profile {profile} differs from what {profile['id']} resolves to now {want}")
            findings += profile_findings(decl, want, manifest["artifacts"])
    extra = sorted(str(p.relative_to(out)) for p in out.rglob("*")
                   if p.is_file() and p.name != MANIFEST_NAME and str(p.relative_to(out)) not in listed)
    for name in extra:
        findings.append(f"{name} is in the directory and the manifest does not describe it")
    return findings


# ---------------------------------------------------------------------------
# The entry
# ---------------------------------------------------------------------------


def run_text(argv: list[str], cwd: pathlib.Path | None = None) -> str | None:
    try:
        run = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=cwd)
    except OSError:
        return None
    return run.stdout if run.returncode == 0 else None


def rustc_identity() -> tuple[str, str]:
    """The compiler's own one line and its host triple, from `rustc -vV`."""
    text = run_text(["rustc", "-vV"])
    if text is None:
        raise RuntimeError("rustc -vV failed")
    fields = dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)
    return (f"rustc {fields['release']} ({fields['commit-hash'][:9]} {fields['commit-date']})", fields["host"])


# The `qcc` variant (its `-V` selector) of each architecture the QNX rows cover: the one the SDP's
# compiler driver is told to compile C for, which is also the one cc-rs passes for these triples.
QNX_QCC_VARIANT = {"aarch64": "gcc_ntoaarch64le_cxx"}


def qnx_cc_identity(platform: dict, command: str) -> str | None:
    """What the SDP's compiler driver reports about the compiler it drives. `qcc` answers neither
    `--version` nor `-dumpversion`; with a variant selected it does answer the preprocessor's macro
    dump, whose `__VERSION__` is the GCC it runs, so that is what is read."""
    arch = platform["triple"].split("-", 1)[0]
    variant = QNX_QCC_VARIANT.get(arch)
    if variant is None:
        raise Refusal(f"platform {platform['id']}: no qcc variant is known for architecture {arch}")
    with tempfile.TemporaryDirectory(prefix="wz-qcc-") as work:
        empty = pathlib.Path(work) / "empty.c"
        empty.write_text("")
        text = run_text([*shlex.split(command), f"-V{variant}", "-E", "-dM", str(empty)])
    for line in (text or "").splitlines():
        if line.startswith("#define __VERSION__ "):
            version = line.split(" ", 2)[2].strip().strip('"')
            return f"{pathlib.Path(shlex.split(command)[0]).name} (GCC {version}, variant {variant})"
    return None


def cc_identity(platform: dict, cross: bool) -> str | None:
    """The first line of the C compiler's `--version`. A cross build must name one it can run."""
    words = platform["triple"].replace("-", "_")
    command = os.environ.get(f"CC_{words}") or (None if cross else os.environ.get("CC") or "cc")
    if command is None:
        raise Refusal(f"CC_{words} is not set")
    text = run_text([*shlex.split(command), "--version"])
    if text is None and cross and platform.get("sdk_kind") == "qnx-sdp":
        identity = qnx_cc_identity(platform, command)
        if identity is not None:
            return identity
        raise Refusal(f"CC_{words} ({command}) answered neither --version nor the qcc macro dump")
    if text is None:
        if cross:
            raise Refusal(f"CC_{words} ({command}) did not answer --version")
        return None
    return text.splitlines()[0] if text.strip() else None


def read_ndk_revision(cc: str) -> str | None:
    """The NDK release a compiler path belongs to: `Pkg.Revision` of the `source.properties` the
    first directory above it that has one. Only the value is returned, never the path."""
    first = shlex.split(cc)[0] if cc.strip() else ""
    here = pathlib.Path(first).resolve().parent if first else None
    while here is not None and here != here.parent:
        props = here / "source.properties"
        if props.is_file():
            for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "Pkg.Revision":
                    return value.strip()
            return None
        here = here.parent
    return None


def read_qnx_sdp_release(target: str) -> str | None:
    """The SDP release a `QNX_TARGET` belongs to: the one directory under the SDP's
    `.packages/metadata/com.qnx.qnx<NNN>` (the release package, not one of its parts), two levels
    above the target directory. None when there is not exactly one, so a tree that holds two
    releases is refused rather than guessed. Only the directory's name is returned, never a path."""
    if not target.strip():
        return None
    root = pathlib.Path(target).resolve().parent.parent
    metadata = root / ".packages" / "metadata"
    if not metadata.is_dir():
        return None
    releases = sorted(entry.name for package in metadata.iterdir()
                      if re.fullmatch(r"com\.qnx\.qnx\d+", package.name) and package.is_dir()
                      for entry in package.iterdir() if entry.is_dir())
    return releases[0] if len(releases) == 1 else None


def sdk_identity(platform: dict, cross: bool) -> dict | None:
    """What identifies the SDK a cross build used; None for a native build (T2).

    Only the kinds the entry can read are read: a platform that names another is refused, so the
    manifest never carries a guessed identity.
    """
    if not cross:
        return None
    kind = platform.get("sdk_kind")
    if kind is None:
        raise Refusal(f"platform {platform['id']} is a cross build and names no sdk_kind")
    if kind == "yocto":
        # The values the SDK's environment script exports, never a path (T2).
        values = {key: os.environ.get(var, "") for key, var in
                  (("revision", "OECORE_SDK_VERSION"), ("target_arch", "OECORE_TARGET_ARCH"),
                   ("target_os", "OECORE_TARGET_OS"))}
        missing = [var for key, var in (("revision", "OECORE_SDK_VERSION"), ("target_arch", "OECORE_TARGET_ARCH"),
                                        ("target_os", "OECORE_TARGET_OS")) if not values[key]]
        if missing:
            raise Refusal(f"platform {platform['id']} names a yocto SDK and {', '.join(missing)} is not set: "
                          "source the SDK's environment script (scripts/yocto-toolchain-env.sh does)")
        return {"kind": kind, **values}
    if kind == "qnx-sdp":
        release = read_qnx_sdp_release(os.environ.get("QNX_TARGET", ""))
        if release is None:
            raise Refusal(f"platform {platform['id']} names a qnx-sdp SDK and QNX_TARGET does not lead to exactly "
                          "one release under .packages/metadata: source the SDP's environment script "
                          "(scripts/qnx-toolchain-env.sh does)")
        return {"kind": kind, "revision": release}
    if kind != "android-ndk":
        raise Refusal(f"platform {platform['id']}: the entry cannot read a `{kind}` SDK")
    cc = os.environ.get(f"CC_{platform['triple'].replace('-', '_')}", "")
    revision = read_ndk_revision(cc)
    if revision is None:
        raise Refusal(f"CC_{platform['triple'].replace('-', '_')} is not inside an NDK "
                      "(no source.properties with a Pkg.Revision above it)")
    return {"kind": kind, "revision": revision}


def unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def search_dirs_of(text: str) -> list[str]:
    """The library directories a GCC or Clang driver states in `-print-search-dirs`, in its order:
    the `libraries: =a:b:...` line."""
    for line in text.splitlines():
        if line.startswith("libraries: "):
            return unique([d for d in line[len("libraries: "):].lstrip("=").split(":") if d])
    return []


def qcc_link_dirs(text: str) -> list[str]:
    """The library directories `qcc -v` hands the linker when it links a program, in the linker's
    order: each `-L`, then the default path `-Y` replaces the built-in one with. `qcc` answers neither
    `-print-file-name` nor `-print-search-dirs` (measured on the QNX 7.1 SDP), and the GCC under it
    states a sysroot the SDP was built in, not the one it links with; the link line is what it does."""
    for line in text.splitlines():
        words = shlex.split(line.rstrip(" \\")) if line.strip() else []
        if not words or not os.path.basename(words[0]).endswith("ld"):
            continue
        dirs, defaults, it = [], [], iter(words[1:])
        for word in it:
            if word == "-L":
                dirs.append(next(it, ""))
            elif word.startswith("-L"):
                dirs.append(word[2:])
            elif word.startswith("-Y"):
                defaults += word[2:].split(":")
        return unique([d for d in dirs + defaults if d])
    return []


def linker_search_dirs(platform: dict) -> list[str]:
    """The directories the platform's linker searches for a library, in its order, as the linker
    driver itself states them, so no list of an SDK's library directories is kept beside the SDK.
    A refusal when the driver states none."""
    variable = f"CARGO_TARGET_{platform['triple'].replace('-', '_').upper()}_LINKER"
    command = os.environ.get(variable, "")
    if not command.strip():
        raise Refusal(f"{variable} is not set, so the SDK's library search cannot be read")
    argv = shlex.split(command)
    if platform.get("sdk_kind") == "qnx-sdp":
        variant = QNX_QCC_VARIANT.get(platform["triple"].split("-", 1)[0])
        if variant is None:
            raise Refusal(f"platform {platform['id']}: no qcc variant is known for its architecture")
        with tempfile.TemporaryDirectory(prefix="wz-qcc-link-") as work:
            source = pathlib.Path(work) / "main.c"
            source.write_text("int main(void) { return 0; }\n")
            try:
                run = subprocess.run([*argv, f"-V{variant}", "-v", "-o", str(pathlib.Path(work) / "main"),
                                      str(source)], capture_output=True, text=True, check=False, cwd=work)
            except OSError:
                run = None
        dirs = qcc_link_dirs(run.stdout + run.stderr) if run is not None and run.returncode == 0 else []
    else:
        dirs = search_dirs_of(run_text([*argv, "-print-search-dirs"]) or "")
    if not dirs:
        raise Refusal(f"platform {platform['id']}: the linker ({argv[0]}) did not state the directories it "
                      "searches for a library")
    return dirs


def sdk_library(platform: dict, soname: str) -> pathlib.Path | None:
    """The SDK's file for a SONAME: the first of the linker's search directories that holds it, which
    is the file the link itself would take. None when no directory holds it."""
    for directory in linker_search_dirs(platform):
        found = pathlib.Path(directory) / soname
        if found.is_file():
            return found
    return None


def sdk_bundle_check(platform: dict, locate=None) -> list[str]:
    """What the lane holds a platform's `bundle_from_sdk` to where its SDK is: every name is found by
    the linker, is the library it names, and needs only what the platform assumes or bundles. Read
    whether or not an artifact needs it today, so the row is a statement checked against its SDK and
    not one first tested by the build that needs it. One line per library."""
    locate = locate or sdk_library
    lines = []
    for soname in platform.get("bundle_from_sdk", []):
        found = locate(platform, soname)
        if found is None:
            raise Refusal(f"platform {platform['id']} bundles {soname} and the SDK's linker does not find it")
        entry = bundled_entry(platform, soname, found.read_bytes())
        needs = ", ".join(f"{n['soname']} ({n['provided_by']})" for n in entry["elf"]["needed"]) or "nothing"
        lines.append(f"{soname}: {entry['size']} B, needs {needs}")
    return lines


def check_toolchain_env(platform: dict, cross: bool) -> None:
    if not cross:
        return
    missing = [name for name in wz_config.toolchain_env(platform) if not os.environ.get(name)]
    if missing:
        raise Refusal(f"platform {platform['id']} builds with variables the caller sets, and these are not: "
                      f"{', '.join(missing)}")


def git_state() -> dict:
    commit = (run_text(["git", "rev-parse", "HEAD"], ROOT) or "").strip()
    dirty = run_text(["git", "status", "--porcelain", "--untracked-files=no"], ROOT)
    return {"commit": commit or None, "tree_clean": dirty is not None and dirty.strip() == ""}


def package_name(package_id: str) -> str:
    """The package a cargo `package_id` names: `path+file:///x/crates/NAME#0.1.0`,
    `path+file:///x/DIR#NAME@0.1.0` and the older `NAME 0.1.0 (path+...)` forms."""
    if "#" in package_id:
        head, tail = package_id.split("#", 1)
        return tail.split("@", 1)[0] if "@" in tail else head.rstrip("/").rsplit("/", 1)[-1]
    return package_id.split(" ", 1)[0]


def cargo_argv(platform: dict, cross: bool, row: dict, cargo_profile: str,
               extra_args: list[str] | None = None, node: dict | None = None) -> list[str]:
    """The cargo command that builds one artifact. A platform whose `std` is `build-std` has no
    prebuilt standard library, so the command builds it (`-Z` needs a nightly cargo, which is the
    caller's to put first, as it is the caller's to provide the SDK). An artifact built from a node
    declaration is a binary of a package outside the crates workspace: its own manifest, and the
    features the declaration asks for."""
    if row.get("input") == "node":
        argv = ["cargo", "build", "--manifest-path", str(ROOT / row["manifest"]), "--bin", row["bin"],
                "--features", ",".join(node["features"]), "--message-format=json-render-diagnostics"]
    else:
        argv = ["cargo", "build", "-p", row["package"], "--message-format=json-render-diagnostics"]
    if cargo_profile == "release":
        argv.append("--release")
    if cross:
        argv += ["--target", platform["triple"]]
        if platform.get("std") == "build-std":
            argv += ["-Z", "build-std=std,panic_abort"]
    return argv + (extra_args or [])


def cargo_build(platform: dict, cross: bool, row: dict, cargo_profile: str,
                extra_args: list[str] | None = None, extra_env: dict[str, str] | None = None,
                node: dict | None = None
                ) -> tuple[pathlib.Path, list[str], dict[str, list[str]]]:
    """Build one artifact; the file, the features cargo built it with, and the features it
    enabled in every package of the build (the union over that package's units).

    `extra_args` and `extra_env` are what a profile adds: the feature selection and the limits.
    `node` is what a declaration adds to a node-built artifact: the generated constants the build
    includes and the budgets it states. That build runs in its package's own directory, so the
    cargo config there (the image's budgets) applies and the declaration's override it.
    """
    argv = cargo_argv(platform, cross, row, cargo_profile, extra_args, node)
    env = {**os.environ, **(extra_env or {})}
    cwd = ROOT / "crates"
    if row.get("input") == "node":
        env = {**env, "WZ_DECLARED_RS": str(node["generated"]), **node["limits"], **node["policies"]}
        cwd = (ROOT / row["manifest"]).parent
    run = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, text=True, check=False, env=env)
    if run.returncode != 0:
        raise RuntimeError(f"cargo build -p {row['package']} failed ({run.returncode})")
    found = None
    resolved: dict[str, set[str]] = {}
    kind = "cdylib" if row["kind"] == "shared-library" else "bin"
    for line in run.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        pid = msg.get("package_id", "")
        resolved.setdefault(package_name(pid), set()).update(msg.get("features", []))
        if package_name(pid) != row["package"]:
            continue
        if kind not in msg["target"]["kind"]:
            continue
        if row.get("input") == "node" and msg["target"]["name"] != row["bin"]:
            continue
        files =[f for f in msg["filenames"] if f.endswith(".so")] if kind == "cdylib" else [msg.get("executable")]
        if files and files[0]:
            found = (pathlib.Path(files[0]), list(msg["features"]))
    if found is None:
        raise RuntimeError(f"cargo built nothing that is the {row['kind']} of {row['package']}")
    return found[0], found[1], {p: sorted(f) for p, f in resolved.items()}


def node_input(decl: dict, rows: list[dict], node_id: str | None, node_file: pathlib.Path | None = None,
               work: pathlib.Path | None = None) -> dict | None:
    """The node declaration the build takes, when an artifact is built from one.

    A node is an input like a profile, resolved (validated, its constants generated) before anything
    is built. It is given one of two ways: a registered name (`--node ID`, a declaration of
    `deploy/nodes/`, whose tracked generated file must be current) or a file (`--node-file PATH`,
    a declaration a consumer wrote, validated the same way and generated into `work`, the build's own
    directory). Either way the node is identified by the digest of the declaration's bytes, which the
    built file carries and the package holds the file to. An artifact built from a declaration with
    none given, a declaration given when no artifact takes one, and both ways at once are each
    refused: the first would build nothing the caller chose, the others would drop a word the caller
    meant.
    """
    wanting = [r["id"] for r in rows if r.get("input") == "node"]
    given = "--node-file" if node_file is not None else "--node" if node_id is not None else None
    if node_id is not None and node_file is not None:
        raise Refusal("--node and --node-file each name the node declaration; give one")
    if not wanting:
        if given is not None:
            raise Refusal(f"{given} names a node declaration, and none of the artifacts is built from one")
        return None
    known = sorted(p.stem for p in wz_node.NODES.glob("*.toml"))
    if given is None:
        raise Refusal(f"{', '.join(wanting)} is built from a node declaration: give a file with --node-file "
                      f"or name a registered one with --node (known: {', '.join(known)})")
    if node_file is not None:
        if work is None:
            raise RuntimeError("a node declaration given as a file needs the build's own directory")
        if not node_file.is_file():
            raise Refusal(f"--node-file {node_file}: no such file")
        try:
            return wz_node.resolve_file(node_file, decl, work)
        except (ValueError, OSError) as err:
            raise Refusal(f"--node-file {node_file.name}: {err}") from err
    if node_id not in known:
        raise Refusal(f"no registered node `{node_id}` (known: {', '.join(known)}); a declaration that is not "
                      "registered is given as a file with --node-file")
    try:
        return wz_node.resolve(node_id, decl)
    except (ValueError, OSError) as err:
        raise Refusal(f"node {node_id}: {err}") from err


def package(decl: dict, platform_id: str, artifact_ids: list[str], out: pathlib.Path, cargo_profile: str,
            profile_id: str | None = None, node_id: str | None = None,
            node_file: pathlib.Path | None = None) -> int:
    """Build, describe and verify; a declaration given as a file is generated into a directory of
    the build's own, which is gone when the build is."""
    with tempfile.TemporaryDirectory(prefix="wz-package-node-") as work:
        return _package(decl, platform_id, artifact_ids, out, cargo_profile, profile_id, node_id, node_file,
                        pathlib.Path(work))


def _package(decl: dict, platform_id: str, artifact_ids: list[str], out: pathlib.Path, cargo_profile: str,
             profile_id: str | None, node_id: str | None, node_file: pathlib.Path | None,
             work: pathlib.Path) -> int:
    platform, rows = preflight(decl, platform_id, artifact_ids)
    node = node_input(decl, rows, node_id, node_file, work)
    declarations = {node["declaration_sha256"]: node} if node else {}
    view = None
    if profile_id is not None:
        # Resolved and applied-or-refused before anything is built or created.
        view = resolve_profile(decl, profile_id)
        for row in rows:
            profile_cargo_args(decl, row, view)
    rustc, host = rustc_identity()
    cross = platform["triple"] != host
    check_toolchain_env(platform, cross)
    if out.exists() and any(out.iterdir()):
        raise Refusal(f"{out} exists and is not empty; the entry does not overwrite")
    created = not out.exists()
    out.mkdir(parents=True, exist_ok=True)
    try:
        toolchain = {"rustc": rustc, "cc": cc_identity(platform, cross), "sdk": sdk_identity(platform, cross)}
        entries = []
        for row in rows:
            built, features, resolved = cargo_build(
                platform, cross, row, cargo_profile,
                profile_cargo_args(decl, row, view) if view else None,
                {k: str(v) for k, v in view["limits"].items()} if view else None,
                node if row.get("input") == "node" else None)
            want = f"lib{row['file']}.so" if row["kind"] == "shared-library" else row["file"]
            if built.name != want:
                raise RuntimeError(f"cargo built {built.name} for {row['id']}, the declaration says {want}")
            sub = "lib" if row["kind"] == "shared-library" else "bin"
            (out / sub).mkdir(exist_ok=True)
            shutil.copyfile(built, out / sub / want)
            # The file a tool runs or loads is the one cargo made, mode and all: an executable
            # copied without its execute bit is a package that cannot be started.
            shutil.copymode(built, out / sub / want)
            blob = (out / sub / want).read_bytes()
            entries.append(artifact_entry(decl, platform, row, f"{sub}/{want}", blob, features, resolved,
                                          declarations))
        bundled = bundle(platform, entries, out)
        inputs = []
        if node is not None:
            # The declaration travels with what was built from it: the bytes the build read.
            (out / "node").mkdir(exist_ok=True)
            (out / declaration_path(node["id"])).write_bytes(node["source"])
            inputs.append(input_entry(node))
        manifest = assemble(decl, platform, git_state(), toolchain, entries, view, bundled, inputs)
        (out / MANIFEST_NAME).write_text(render(manifest), encoding="utf-8")
        findings = verify_dir(out, decl)
        if findings:
            raise RuntimeError("the manifest just written does not verify: " + "; ".join(findings))
    except BaseException:
        # A refusal and a failure alike leave nothing a tool could read as a package.
        if created:
            shutil.rmtree(out)
        else:
            for leftover in out.iterdir():
                shutil.rmtree(leftover) if leftover.is_dir() else leftover.unlink()
        raise
    print(f"  wz-package: {platform['id']}: {len(entries)} artifact(s) and {len(bundled)} bundled "
          f"librar{'y' if len(bundled) == 1 else 'ies'} in {out}, manifest verified")
    return 0


# ---------------------------------------------------------------------------
# Self-test: synthetic artifacts, so every refusal and finding has a file whose defect is known
# ---------------------------------------------------------------------------


def _stamp(family: str, revision: int = 1, layout: dict | None = None) -> bytes:
    return json.dumps({"schema": 1, "family": family, "revision": revision, "layout": layout or {}},
                      separators=(",", ":")).encode() + b"\x00"


def _facts(roles: list[str] | None = None, lists: dict[str, list[str]] | None = None) -> bytes:
    lists = {"driver_roles": roles} if lists is None else lists
    return json.dumps({"schema": 1, "lists": lists}, separators=(",", ":")).encode() + b"\x00"


# The machine, the loader and the C library's version needs a synthetic file of each platform has, so
# a synthetic package reads like one of that platform (the selftest's default is the x86_64 host).
SYNTHETIC_TARGETS = {
    "x86_64-unknown-linux-gnu": (62, "/lib64/ld-linux-x86-64.so.2", [("libc.so.6", ["GLIBC_2.17", "GLIBC_2.34"])]),
    "aarch64-linux-android": (183, "/system/bin/linker64", []),
}


def _synthetic(row: dict, needed: list[str], roles: list[str] | None = None, family: str | None = None,
               revision: int = 1, facts_lists: dict[str, list[str]] | None = None,
               triple: str = "x86_64-unknown-linux-gnu") -> bytes:
    machine, interp, verneed = SYNTHETIC_TARGETS[triple]
    notes = [(elf_facts.STAMP_SECTION, "wz", 1, _stamp(family or row["family"], revision))]
    if roles is not None:
        notes.append((elf_facts.FACTS_SECTION, "wz", 2, _facts(roles)))
    elif facts_lists is not None:
        notes.append((elf_facts.FACTS_SECTION, "wz", 2, _facts(lists=facts_lists)))
    return elf_facts.build_test_elf(
        notes_=notes, needed=needed, machine=machine,
        soname=f"lib{row['file']}.so" if row["kind"] == "shared-library" else None,
        interp=interp if row["kind"] == "executable" else None,
        verneed=verneed)


# ---------------------------------------------------------------------------
# Fixtures (docs/target-build-contract.md step 7): one corpus a consumer's reader and this gate are
# both held to
# ---------------------------------------------------------------------------

FIXTURES = ROOT / "deploy" / "fixtures" / "manifests"
FIXTURE_INDEX = "index.json"
FIXTURE_SCHEMA = 1
# What a reader needs to see a defect: the manifest's keys (`shape`), the manifest alone, read for
# its own consistency (`manifest`), or the files it describes, measured again (`files`).
FIXTURE_LEVELS = {
    "shape": "the keys of the manifest, in order, none more (shape_findings)",
    "manifest": "the manifest alone, read for its own consistency (the closure, the inputs, the paths)",
    "files": "the files the manifest describes, measured again from their bytes",
}
FIXTURE_BUILT_FROM = {"commit": "0" * 40, "tree_clean": True}


def _fixture_packages(decl: dict) -> dict[str, tuple[str, dict, dict[str, bytes]]]:
    """The valid synthetic packages, by name: (platform id, manifest, files by path). Each is what
    `package` writes for its inputs, made from synthetic files instead of a build."""
    arts = {a["id"]: a for a in decl["artifacts"]}
    plats = {p["id"]: p for p in decl["platforms"]}
    toolchain = {"rustc": "rustc 0 (synthetic)", "cc": None, "sdk": None}
    out: dict[str, tuple[str, dict, dict[str, bytes]]] = {}

    host = plats["linux-x86_64-glibc"]
    needs = [n for n in host["system_assumed"] if not n.startswith("ld-")]
    pico, demo = arts["capi-pico"], arts["ap-demo"]
    files = {"lib/libwz_capi_pico.so": _synthetic(pico, needs),
             "bin/wz-ap-demo": _synthetic(demo, needs, roles=["publish", "subscribe"])}
    resolved = {"wz-runtime-tokio": sorted(r["feature"] for r in decl["package_features"])}
    entries = [artifact_entry(decl, host, pico, "lib/libwz_capi_pico.so", files["lib/libwz_capi_pico.so"],
                              ["peer", "scout", "link-udp", "multi-thread"]),
               artifact_entry(decl, host, demo, "bin/wz-ap-demo", files["bin/wz-ap-demo"],
                              ["zenoh-config"], resolved)]
    out["host-library-and-executable"] = (host["id"], assemble(decl, host, FIXTURE_BUILT_FROM, toolchain, entries),
                                          files)
    # The same package as an entry before the split wrote it: valid, its bound not split.
    unsplit = [{k: v for k, v in e.items() if k in UNSPLIT_ARTIFACT_KEYS} for e in entries]
    out["host-unsplit-bound"] = (host["id"], assemble(decl, host, FIXTURE_BUILT_FROM, toolchain, unsplit), files)

    android = plats["android-arm64"]
    runtime = android["bundle_from_sdk"][0]
    triple = android["triple"]
    lib = _synthetic(pico, [*android["system_assumed"], runtime], triple=triple)
    bundled_blob = elf_facts.build_test_elf(needed=list(android["system_assumed"]), soname=runtime,
                                            machine=SYNTHETIC_TARGETS[triple][0])
    files = {"lib/libwz_capi_pico.so": lib, bundled_path(runtime): bundled_blob}
    entries = [artifact_entry(decl, android, pico, "lib/libwz_capi_pico.so", lib, ["peer", "link-udp"])]
    bundled = [bundled_entry(android, runtime, bundled_blob)]
    sdk_toolchain = {**toolchain, "sdk": {"kind": "android-ndk", "revision": "0 (synthetic)"}}
    out["android-bundled-runtime"] = (android["id"], assemble(decl, android, FIXTURE_BUILT_FROM, sdk_toolchain,
                                                              entries, None, bundled), files)

    node_row = arts["declared-node"]
    view = wz_node.resolve("slot-answerer", decl)
    blob = _synthetic(node_row, needs, facts_lists={"node_id": [view["id"]],
                                                    "declaration_sha256": [view["declaration_sha256"]]})
    files = {"bin/declared-node": blob, declaration_path(view["id"]): view["source"]}
    entries = [artifact_entry(decl, host, node_row, "bin/declared-node", blob, view["features"], None,
                              {view["declaration_sha256"]: view})]
    out["host-declared-node"] = (host["id"], assemble(decl, host, FIXTURE_BUILT_FROM, toolchain, entries, None,
                                                      None, [input_entry(view)]), files)
    return out


def _flip_last(blob: bytes) -> bytes:
    return blob[:-1] + bytes([blob[-1] ^ 0xFF])


# The invalid synthetic packages: (name, the valid package it damages, level, the words of the
# finding this gate reports, the damage to (manifest, files)). Each has one defect.
FIXTURE_DAMAGES = [
    ("shape-extra-key", "host-library-and-executable", "shape", "keys",
     lambda m, f: m.__setitem__("extra", 1)),
    ("manifest-unknown-schema", "host-library-and-executable", "manifest", "schema is 99",
     lambda m, f: m.__setitem__("schema", 99)),
    ("shape-artifact-key-missing", "host-library-and-executable", "shape", "keys",
     lambda m, f: m["artifacts"][0].pop("sha256")),
    ("shape-requires-also-may", "host-library-and-executable", "shape", "in both requires and may_require",
     lambda m, f: m["artifacts"][0]["may_require"].insert(0, "entropy")),
    ("shape-requires-not-the-bound", "host-library-and-executable", "shape", "is not requires and may_require",
     lambda m, f: m["artifacts"][0]["device_requires"].remove("sockets-udp")),
    ("shape-split-and-unsplit", "host-library-and-executable", "shape", "split the bound in one and not",
     lambda m, f: [m["artifacts"][1].pop(k) for k in ("requires", "may_require")]),
    ("manifest-path-leaves-directory", "host-library-and-executable", "manifest", "relative path",
     lambda m, f: m["artifacts"][0].__setitem__("path", "../libwz_capi_pico.so")),
    ("manifest-bundled-nothing-needs", "android-bundled-runtime", "manifest", "nothing in the package needs it",
     lambda m, f: m["artifacts"][0]["elf"]["needed"].pop()),
    ("manifest-bundled-entry-missing", "android-bundled-runtime", "manifest", "the manifest bundles no",
     lambda m, f: m.__setitem__("bundled", [])),
    ("manifest-input-nothing-built-from", "host-declared-node", "manifest", "nothing in it was built from it",
     lambda m, f: m["artifacts"][0]["provides"][0].__setitem__("declaration_sha256", ["0" * 64])),
    ("files-artifact-byte-changed", "host-library-and-executable", "files", "sha256",
     lambda m, f: f.__setitem__("lib/libwz_capi_pico.so", _flip_last(f["lib/libwz_capi_pico.so"]))),
    ("files-artifact-missing", "host-library-and-executable", "files", "is missing",
     lambda m, f: f.pop("bin/wz-ap-demo")),
    ("files-stray-file", "host-library-and-executable", "files", "does not describe",
     lambda m, f: f.__setitem__("lib/stray.so", b"stray")),
    ("files-bundled-other-library", "android-bundled-runtime", "files", "SONAME",
     lambda m, f: f.__setitem__(bundled_path("libc++_shared.so"), elf_facts.build_test_elf(
         needed=["libc.so"], soname="libother.so", machine=183))),
    ("files-declaration-edited", "host-declared-node", "files", "sha256",
     lambda m, f: f.__setitem__("node/slot-answerer.toml", f["node/slot-answerer.toml"] + b"# edited\n")),
]


def fixture_corpus(decl: dict) -> list[dict]:
    """Every synthetic case: its path under the corpus, the platform, the expected verdict, and the
    files of the package (the manifest among them), valid ones first."""
    packages = _fixture_packages(decl)
    cases = []
    for name, (platform_id, manifest, files) in packages.items():
        cases.append({"path": f"synthetic/{name}", "platform": platform_id, "expect": {"verdict": "valid"},
                      "files": {**files, MANIFEST_NAME: render(manifest).encode()}})
    for name, base, level, words, damage in FIXTURE_DAMAGES:
        platform_id, manifest, files = packages[base]
        manifest, files = copy.deepcopy(manifest), dict(files)
        damage(manifest, files)
        cases.append({"path": f"synthetic/{name}", "platform": platform_id,
                      "expect": {"verdict": "invalid", "level": level, "finding": words},
                      "files": {**files, MANIFEST_NAME: render(manifest).encode()}})
    return cases


def fixture_index(cases: list[dict], measured: list[pathlib.Path]) -> dict:
    """The corpus's own description, which a reader reads first: each fixture's path, whether it was
    measured from a build or made here, its platform and the verdict this gate gives it."""
    entries = [{"path": c["path"], "origin": "synthetic", "platform": c["platform"], "expect": c["expect"]}
               for c in cases]
    for path in measured:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        entries.append({"path": f"measured/{path.name}", "origin": "measured",
                        "platform": manifest["platform"]["id"], "expect": {"verdict": "valid", "files": False}})
    return {"schema": FIXTURE_SCHEMA, "manifest_schema": MANIFEST_SCHEMA, "levels": FIXTURE_LEVELS,
            "fixtures": entries}


def _write_case(root: pathlib.Path, case: dict) -> None:
    for rel, blob in case["files"].items():
        target = root / case["path"] / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)


def write_fixtures(decl: dict, root: pathlib.Path = FIXTURES) -> int:
    """Write the synthetic corpus and the index; the measured manifests are kept as they are."""
    cases = fixture_corpus(decl)
    if (root / "synthetic").exists():
        shutil.rmtree(root / "synthetic")
    for case in cases:
        _write_case(root, case)
    measured = sorted((root / "measured").glob("*.json")) if (root / "measured").is_dir() else []
    (root / FIXTURE_INDEX).write_text(json.dumps(fixture_index(cases, measured), indent=2) + "\n", encoding="utf-8")
    print(f"  wz-package: wrote {len(cases)} synthetic fixture(s) and the index of {len(measured)} measured one(s)")
    return 0


def fixture_findings(decl: dict, root: pathlib.Path = FIXTURES) -> list[str]:
    """What is wrong with the corpus: synthetic cases that are not what this entry makes now (byte for
    byte, none missing, none more), an index that does not describe the corpus, a case this gate does
    not judge as the index says (a valid one with a finding, an invalid one without its words, or one
    whose level is not where the defect is), and a measured manifest whose shape is not this schema's
    or that was not built from a committed tree."""
    findings: list[str] = []
    cases = fixture_corpus(decl)
    stale = "regenerate with wz_package.py --write-fixtures"
    want = {f"{c['path']}/{rel}": blob for c in cases for rel, blob in c["files"].items()}
    synthetic = root / "synthetic"
    have = {str(p.relative_to(root)): p.read_bytes() for p in synthetic.rglob("*") if p.is_file()} \
        if synthetic.is_dir() else {}
    for rel in sorted(set(want) - set(have)):
        findings.append(f"fixture {rel} is missing: {stale}")
    for rel in sorted(set(have) - set(want)):
        findings.append(f"fixture {rel} is not one this entry makes: {stale}")
    for rel in sorted(set(want) & set(have)):
        if want[rel] != have[rel]:
            findings.append(f"fixture {rel} is not what this entry makes now: {stale}")
    measured = sorted((root / "measured").glob("*.json")) if (root / "measured").is_dir() else []
    index_path = root / FIXTURE_INDEX
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        findings.append(f"{FIXTURE_INDEX} is not readable: {err}")
    else:
        if index != fixture_index(cases, measured):
            findings.append(f"{FIXTURE_INDEX} does not describe the corpus: {stale}")
    with tempfile.TemporaryDirectory(prefix="wz-fixtures-") as work:
        for case in cases:
            _write_case(pathlib.Path(work), case)
            directory = pathlib.Path(work) / case["path"]
            manifest = json.loads(case["files"][MANIFEST_NAME])
            found = verify_dir(directory, decl)
            expect = case["expect"]
            if expect["verdict"] == "valid":
                if found:
                    findings.append(f"{case['path']} is indexed valid and this gate finds {found}")
                continue
            if not any(expect["finding"] in f for f in found):
                findings.append(f"{case['path']} is indexed invalid ({expect['finding']!r}) and this gate "
                                f"finds {found}")
            in_shape = bool(shape_findings(manifest))
            if in_shape != (expect["level"] == "shape"):
                findings.append(f"{case['path']} is indexed at level {expect['level']} and its shape is "
                                f"{'not ' if not in_shape else ''}what breaks")
    for path in measured:
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as err:
            findings.append(f"measured/{path.name} is not JSON: {err}")
            continue
        for problem in shape_findings(manifest):
            findings.append(f"measured/{path.name}: {problem}: record it again from a build "
                            "(wz_package.py --record-measured DIR)")
        if isinstance(manifest, dict) and manifest.get("schema") != MANIFEST_SCHEMA:
            findings.append(f"measured/{path.name} is schema {manifest.get('schema')!r}, this entry writes "
                            f"{MANIFEST_SCHEMA}")
        if isinstance(manifest, dict) and not (manifest.get("built_from") or {}).get("tree_clean"):
            findings.append(f"measured/{path.name} was built from a tree with uncommitted changes")
    return findings


def record_measured(decl: dict, directory: pathlib.Path, root: pathlib.Path = FIXTURES) -> int:
    """Record a package this entry built and verified as a measured fixture: its manifest, named by
    the platform (and the node, for a node package), from a committed tree only. The files stay out of
    the tree; the measured fixtures are read for their shape and values, the synthetic ones for every
    level."""
    findings = verify_dir(directory, decl)
    if findings:
        raise Refusal(f"{directory} does not verify: " + "; ".join(findings))
    text = (directory / MANIFEST_NAME).read_text(encoding="utf-8")
    manifest = json.loads(text)
    if not manifest["built_from"]["tree_clean"]:
        raise Refusal(f"{directory} was built from a tree with uncommitted changes; a measured fixture is "
                      "built from a commit")
    name = manifest["platform"]["id"] + "".join(f"-{i['id']}" for i in manifest["inputs"])
    (root / "measured").mkdir(parents=True, exist_ok=True)
    (root / "measured" / f"{name}.json").write_text(text, encoding="utf-8")
    write_fixtures(decl, root)
    print(f"  wz-package: recorded measured/{name}.json")
    return 0


def _selftest() -> int:
    decl = wz_config.load_decl()

    def expect(label: str, condition: bool) -> None:
        if not condition:
            raise AssertionError(f"selftest: {label}")

    def refuses(label: str, words: str, call) -> None:
        try:
            call()
        except Refusal as err:
            expect(f"{label} (the refusal does not say {words!r}: {err})", words in str(err))
            return
        raise AssertionError(f"selftest: {label}: nothing was refused")

    host = "linux-x86_64-glibc"
    assumed = next(p for p in decl["platforms"] if p["id"] == host)["system_assumed"]
    needs = [n for n in assumed if n != "ld-linux-x86-64.so.2"]
    platform, rows = preflight(decl, host, ["ap-demo", "capi-pico"])
    expect("artifacts come out in declaration order, not the caller's", [r["id"] for r in rows] == ["capi-pico", "ap-demo"])

    # The refusals before a build starts.
    refuses("an undeclared platform", "no platform", lambda: preflight(decl, "nowhere", ["capi-pico"]))
    unassessed_decl = copy.deepcopy(decl)
    for p in unassessed_decl["platforms"]:
        if p["id"] == "linux-aarch64-glibc":
            p.pop("os_provides", None)
    refuses("an unassessed platform", "unassessed",
            lambda: preflight(unassessed_decl, "linux-aarch64-glibc", ["capi-pico"]))
    refuses("an undeclared artifact", "no artifact", lambda: preflight(decl, host, ["nope"]))
    cross_platform = next(p for p in decl["platforms"] if p["id"] == "android-arm64")
    saved = {k: os.environ.pop(k) for k in wz_config.toolchain_env(cross_platform) if k in os.environ}
    try:
        refuses("a cross build with no toolchain variable", "CC_aarch64_linux_android",
                lambda: check_toolchain_env(cross_platform, True))
        check_toolchain_env(cross_platform, False)
    finally:
        os.environ.update(saved)

    # A clean package: assemble, write, verify.
    pico = next(a for a in decl["artifacts"] if a["id"] == "capi-pico")
    demo = next(a for a in decl["artifacts"] if a["id"] == "ap-demo")
    pico_blob = _synthetic(pico, needs)
    demo_blob = _synthetic(demo, needs, roles=["publish", "subscribe"])
    pico_features = ["peer", "scout", "link-udp", "multi-thread"]
    demo_features = ["zenoh-config", "other"]
    # What cargo enabled in the runtime for the default build: every feature the declaration assessed.
    demo_resolved = {"wz-runtime-tokio": sorted(r["feature"] for r in decl["package_features"])}
    with tempfile.TemporaryDirectory(prefix="wz-package-") as work:
        out = pathlib.Path(work) / "out"
        (out / "lib").mkdir(parents=True)
        (out / "bin").mkdir()
        (out / "lib" / "libwz_capi_pico.so").write_bytes(pico_blob)
        (out / "bin" / "wz-ap-demo").write_bytes(demo_blob)
        entries = [
            artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so", pico_blob, pico_features),
            artifact_entry(decl, platform, demo, "bin/wz-ap-demo", demo_blob, demo_features, demo_resolved),
        ]
        manifest = assemble(decl, platform, {"commit": "0" * 40, "tree_clean": True},
                            {"rustc": "rustc 0", "cc": None, "sdk": None}, entries)
        expect("the shape of a manifest it wrote is clean", shape_findings(manifest) == [])
        manifest_path = out / MANIFEST_NAME
        manifest_path.write_text(render(manifest), encoding="utf-8")
        expect("the same inputs give the same bytes", render(manifest) == render(copy.deepcopy(manifest)))
        expect("a clean directory verifies", verify_dir(out, decl) == [])
        demo_entry = entries[1]
        expect("the session node is present when its feature is on",
               [p["role"] for p in demo_entry["provides"]] == ["session-node", "traffic-driver"])
        expect("the driver roles are the facts note's, in the manifest",
               demo_entry["provides"][1]["driver_roles"] == ["publish", "subscribe"])
        expect("a library's device_requires is the union of what its capabilities may ask",
               entries[0]["device_requires"]
               == ["entropy", "interface-list", "multicast", "sockets-tcp", "sockets-udp", "threads"])
        expect("an executable's is the base, its own package's and what its runtime features may ask",
               demo_entry["device_requires"]
               == ["entropy", "filesystem", "interface-list", "multicast", "sockets-tcp", "sockets-udp",
                   "threads", "wall-clock"]
               and demo_entry["unassessed_features"] == [])
        expect("what every run asks for is required, and the rest of the bound may be asked",
               all(e["requires"] == ["entropy", "threads"] for e in entries)
               and entries[0]["may_require"] == ["interface-list", "multicast", "sockets-tcp", "sockets-udp"]
               and demo_entry["may_require"] == ["filesystem", "interface-list", "multicast", "sockets-tcp",
                                                 "sockets-udp", "wall-clock"])
        unknown = artifact_entry(decl, platform, demo, "bin/wz-ap-demo", demo_blob, demo_features,
                                 {"wz-runtime-tokio": [*demo_resolved["wz-runtime-tokio"], "transport-link-ws"]})
        expect("an enabled runtime feature nobody assessed makes it unknown and is named",
               unknown["device_requires"] is None
               and unknown["unassessed_features"] == ["wz-runtime-tokio/transport-link-ws"])
        expect("an unassessed feature leaves what every run requires known, and what it may ask unknown",
               unknown["requires"] == ["entropy", "threads"] and unknown["may_require"] is None)
        expect("the shape of an unknown entry keeps the invariant", requires_findings("u", unknown) == [])

        def broken(**changed) -> list[str]:
            return requires_findings("e", {**demo_entry, **changed})

        expect("a facility in both requires and may_require is a finding",
               "in both" in " ".join(broken(may_require=["entropy", *demo_entry["may_require"]])))
        expect("a device_requires that is not the two together is a finding",
               "not requires and may_require together" in " ".join(broken(device_requires=["threads"])))
        expect("a null on one side of the bound and not the other is a finding",
               "one of may_require" in " ".join(broken(may_require=None, unassessed_features=["p/f"])))
        expect("an unknown bound with no unassessed feature is a finding",
               "no unassessed feature" in " ".join(broken(may_require=None, device_requires=None)))
        expect("a known bound with an unassessed feature is a finding",
               "is not empty" in " ".join(broken(unassessed_features=["p/f"])))
        expect("a manifest whose entry breaks the invariant has a shape finding",
               any("in both" in f for f in shape_findings(
                   {**manifest, "artifacts": [{**demo_entry, "requires": ["entropy", "sockets-tcp", "threads"]}]})))
        bare = artifact_entry(decl, platform, demo, "bin/wz-ap-demo", demo_blob, demo_features)
        expect("an executable with no resolved runtime features asks for the base and its own package's",
               bare["device_requires"] == sorted(set(decl["os_base"]) | {"filesystem", "wall-clock"}))
        expect("the glibc floor is measured", entries[0]["elf"]["os_floor"]["glibc"] == "GLIBC_2.34")
        no_config = artifact_entry(decl, platform, demo, "bin/wz-ap-demo", demo_blob, ["other"], demo_resolved)
        expect("the session node is absent when its feature is off",
               [p["role"] for p in no_config["provides"]] == ["traffic-driver"])

        def verified_after(label: str, damage, words: str) -> None:
            """Damage a copy of the clean directory, and the gate must say `words`."""
            copy_dir = pathlib.Path(work) / "copy"
            if copy_dir.exists():
                shutil.rmtree(copy_dir)
            shutil.copytree(out, copy_dir)
            damage(copy_dir)
            found = verify_dir(copy_dir, decl)
            expect(f"{label}: not reported ({found})", any(words in f for f in found))

        def flip(dir_: pathlib.Path) -> None:
            file = dir_ / "bin" / "wz-ap-demo"
            data = bytearray(file.read_bytes())
            data[-1] ^= 0xFF
            file.write_bytes(bytes(data))

        verified_after("a byte of an artifact changed", flip, "sha256")
        verified_after("an artifact replaced by one that needs another library",
                       lambda d: (d / "bin" / "wz-ap-demo").write_bytes(_synthetic(demo, [*needs, "libfoo.so.1"],
                                                                                    roles=["publish", "subscribe"])),
                       "libfoo.so.1")
        verified_after("an artifact of another family",
                       lambda d: (d / "bin" / "wz-ap-demo").write_bytes(
                           _synthetic(demo, needs, roles=["publish", "subscribe"], family="capi-c")),
                       "family")
        verified_after("an artifact removed", lambda d: (d / "bin" / "wz-ap-demo").unlink(), "is missing")
        verified_after("a file the manifest does not describe",
                       lambda d: (d / "lib" / "stray.so").write_bytes(b"x"), "does not describe")
        verified_after("a revision moved in the file only",
                       lambda d: (d / "lib" / "libwz_capi_pico.so").write_bytes(_synthetic(pico, needs, revision=9)),
                       "revision")

        def edit_manifest(dir_: pathlib.Path, fn) -> None:
            data = json.loads((dir_ / MANIFEST_NAME).read_text())
            fn(data)
            (dir_ / MANIFEST_NAME).write_text(json.dumps(data, indent=2) + "\n")

        verified_after("a hash edited by hand", lambda d: edit_manifest(
            d, lambda m: m["artifacts"][0].__setitem__("sha256", "0" * 64)), "sha256")
        verified_after("a feature list edited so a role appears or goes", lambda d: edit_manifest(
            d, lambda m: m["artifacts"][1].__setitem__("features", ["other"])), "provides")
        verified_after("a key added to the manifest", lambda d: edit_manifest(
            d, lambda m: m.__setitem__("extra", 1)), "keys")
        verified_after("a key missing from an artifact", lambda d: edit_manifest(
            d, lambda m: m["artifacts"][0].pop("sha256")), "keys")
        verified_after("an unknown schema", lambda d: edit_manifest(d, lambda m: m.__setitem__("schema", 99)), "schema")
        verified_after("a platform edited away from its declaration", lambda d: edit_manifest(
            d, lambda m: m["platform"].__setitem__("triple", "aarch64-linux-android")), "differs from its declaration")
        verified_after("a path that leaves the directory", lambda d: edit_manifest(
            d, lambda m: m["artifacts"][0].__setitem__("path", "../x")), "relative path")
        verified_after("the manifest removed", lambda d: (d / MANIFEST_NAME).unlink(), "is missing")
        verified_after("a manifest that is not JSON", lambda d: (d / MANIFEST_NAME).write_text("{"), "not readable")

    # The refusals while describing a build.
    refuses("a NEEDED nobody assumed", "libfoo.so.1",
            lambda: artifact_entry(decl, platform, demo, "bin/wz-ap-demo",
                                   _synthetic(demo, [*needs, "libfoo.so.1"], roles=["publish"]), demo_features))
    refuses("a stamp of another family", "family",
            lambda: artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so",
                                   _synthetic(pico, needs, family="capi-c"), pico_features))
    refuses("an executable built without its facts note", "facts note",
            lambda: artifact_entry(decl, platform, demo, "bin/wz-ap-demo", _synthetic(demo, needs), demo_features))
    # A node built from a declaration (T8, docs/target-build-contract.md 5b): the file says which node
    # it is and which declaration it was built from, and the entry holds both to the declaration now.
    node_row = next(a for a in decl["artifacts"] if a["id"] == "declared-node")
    view = wz_node.resolve("slot-answerer", decl)
    held = {view["declaration_sha256"]: view}
    node_lists = {"node_id": ["slot-answerer"], "declaration_sha256": [view["declaration_sha256"]]}

    def node_file(**changed) -> bytes:
        return _synthetic(node_row, needs, facts_lists={**node_lists, **changed})

    def node_entry(blob: bytes, features: list[str] | None = None, plat: dict | None = None,
                   dec: dict | None = None) -> dict:
        return artifact_entry(dec or decl, plat or platform, node_row, "bin/declared-node", blob,
                              view["features"] if features is None else features, None, held)

    described = node_entry(node_file())
    expect("a node's role carries its id and the declaration's digest, read from the file",
           described["provides"] == [{"role": "declared-node", **node_lists}])
    expect("a node asks for entropy and the socket its endpoint uses on every run, and nothing more",
           described["requires"] == described["device_requires"] == ["entropy", "sockets-tcp"]
           and described["may_require"] == [] and described["unassessed_features"] == [])

    def node_package(where: pathlib.Path, resolved: dict, blob: bytes) -> pathlib.Path:
        """A package of one node file and the declaration it was built from, as `package` writes it."""
        (where / "bin").mkdir(parents=True)
        (where / "bin" / "declared-node").write_bytes(blob)
        (where / "node").mkdir()
        (where / declaration_path(resolved["id"])).write_bytes(resolved["source"])
        entry = artifact_entry(decl, platform, node_row, "bin/declared-node", blob, resolved["features"], None,
                               {resolved["declaration_sha256"]: resolved})
        manifest = assemble(decl, platform, {"commit": "0" * 40, "tree_clean": True},
                            {"rustc": "rustc 0", "cc": None, "sdk": None}, [entry], None, None,
                            [input_entry(resolved)])
        expect("the shape of a node manifest is clean", shape_findings(manifest) == [])
        (where / MANIFEST_NAME).write_text(render(manifest), encoding="utf-8")
        return where

    with tempfile.TemporaryDirectory(prefix="wz-package-node-") as node_work:
        root = pathlib.Path(node_work)
        node_out = node_package(root / "out", view, node_file())
        expect(f"a clean node directory verifies ({verify_dir(node_out, decl)})", verify_dir(node_out, decl) == [])
        expect("the package carries the declaration's bytes, named by the node's id",
               (node_out / "node" / "slot-answerer.toml").read_bytes() == (wz_node.NODES / "slot-answerer.toml").read_bytes())
        # A declaration nobody registered: a consumer's file, which the package carries and verify
        # resolves from those bytes alone.
        (root / "mine").mkdir()
        mine = root / "mine" / "slot-answerer.toml"
        mine.write_text(view["source"].decode().replace('help = "', 'help = "A copy outside the registry. ', 1))
        (root / "gen").mkdir()
        outside = wz_node.resolve_file(mine, decl, root / "gen")
        expect("a declaration outside the registry has a digest of its own",
               outside["declaration_sha256"] != view["declaration_sha256"])
        foreign = node_package(root / "foreign", outside,
                               node_file(declaration_sha256=[outside["declaration_sha256"]]))
        expect(f"a package built from a declaration nobody registered verifies from what it carries "
               f"({verify_dir(foreign, decl)})", verify_dir(foreign, decl) == [])

        def node_found(label: str, damage, words: str) -> None:
            """Damage a copy of the clean node package, and the gate must say `words`."""
            copy_dir = root / "copy"
            if copy_dir.exists():
                shutil.rmtree(copy_dir)
            shutil.copytree(node_out, copy_dir)
            damage(copy_dir)
            found = verify_dir(copy_dir, decl)
            expect(f"{label}: not reported ({found})", any(words in f for f in found))

        def edit_node_manifest(fn):
            def damage(dir_: pathlib.Path) -> None:
                data = json.loads((dir_ / MANIFEST_NAME).read_text())
                fn(data)
                (dir_ / MANIFEST_NAME).write_text(json.dumps(data, indent=2) + "\n")
            return damage

        def flip_declaration(dir_: pathlib.Path) -> None:
            file = dir_ / "node" / "slot-answerer.toml"
            file.write_bytes(file.read_bytes() + b"# edited after the build\n")

        node_found("a node file built from another declaration",
                   lambda d: (d / "bin" / "declared-node").write_bytes(node_file(declaration_sha256=["0" * 64])),
                   "nobody declares")
        node_found("the carried declaration edited after the build", flip_declaration, "sha256")
        node_found("the carried declaration edited after the build, seen from the node", flip_declaration,
                   "nobody declares")
        node_found("the carried declaration removed", lambda d: (d / "node" / "slot-answerer.toml").unlink(),
                   "is missing")
        node_found("the declaration's entry removed from the manifest, its file left",
                   edit_node_manifest(lambda m: m["inputs"].pop()), "does not describe")
        node_found("a declaration path that leaves the directory",
                   edit_node_manifest(lambda m: m["inputs"][0].__setitem__("path", "../slot-answerer.toml")),
                   "inside the directory")
        node_found("a carried declaration nothing was built from",
                   edit_node_manifest(lambda m: m["artifacts"][0]["provides"][0].__setitem__(
                       "declaration_sha256", ["0" * 64])), "nothing in it was built from it")

        def invalid_declaration(dir_: pathlib.Path) -> None:
            file = dir_ / "node" / "slot-answerer.toml"
            file.write_bytes(file.read_bytes().replace(b"schema = 1\n", b""))
            data = json.loads((dir_ / MANIFEST_NAME).read_text())
            data["inputs"][0]["sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
            data["inputs"][0]["size"] = len(file.read_bytes())
            (dir_ / MANIFEST_NAME).write_text(json.dumps(data, indent=2) + "\n")

        node_found("a carried declaration that does not validate", invalid_declaration, "does not resolve")
    refuses("a node file whose declaration the package does not carry", "nobody declares",
            lambda: node_entry(node_file(declaration_sha256=["0" * 64])))
    refuses("a node file that names another node than its declaration", "says it is the node `nope`",
            lambda: node_entry(node_file(node_id=["nope"])))
    refuses("a node file with no facts note", "has no single",
            lambda: node_entry(_synthetic(node_row, needs)))
    refuses("a node file with two ids", "has no single",
            lambda: node_entry(node_file(node_id=["slot-answerer", "other"])))
    refuses("a node built with features its declaration does not ask for", "asks for",
            lambda: node_entry(node_file(), features=["declared", "tls"]))
    expect("the package's default feature, which cargo lists, is not a choice",
           node_entry(node_file(), features=["declared", "default"])["features"] == ["declared", "default"])
    no_tcp = copy.deepcopy(decl)
    for p in no_tcp["platforms"]:
        if p["id"] == host:
            p["os_provides"] = [f for f in p["os_provides"] if f != "sockets-tcp"]
    refuses("a node whose endpoint asks for a socket the platform lacks",
            "which platform linux-x86_64-glibc does not provide",
            lambda: node_entry(node_file(), plat=next(p for p in no_tcp["platforms"] if p["id"] == host),
                               dec=no_tcp))
    # No platform row names an operating system the port lacks, so one is made: the Android row moved
    # to an OS nobody ported to.
    no_port = copy.deepcopy(decl)
    for p in no_port["platforms"]:
        if p["id"] == "android-arm64":
            p["os"] = "haiku"
    refuses("a node for a platform whose operating system has no port",
            "operating system haiku): its runtime is the posix port, which is written for Linux, "
            "Android and QNX Neutrino only",
            lambda: preflight(no_port, "android-arm64", ["declared-node"]))
    plain, nodes = lane_plan(no_port, "android-arm64")
    expect("the lane asks a platform whose operating system has no port for no node",
           nodes == [] and "declared-node" not in plain and plain != [])
    for with_port in ("android-arm64", "qnx710-iosock-aarch64", "qnx710-iopkt-aarch64"):
        expect(f"a node is accepted for the {with_port} platform, whose port exists",
               preflight(decl, with_port, ["declared-node"])[1] == [node_row])
    registered = sorted(p.stem for p in wz_node.NODES.glob("*.toml"))
    for with_port in ("android-arm64", "qnx710-iosock-aarch64", "linux-aarch64-glibc"):
        plain, nodes = lane_plan(decl, with_port)
        expect(f"the lane asks {with_port} for every registered node and the artifacts that need none",
               nodes == registered and registered != [] and "declared-node" not in plain)
    refuses("a lane plan for a platform nobody declared", "no platform `nope`",
            lambda: lane_plan(decl, "nope"))
    expect("a node is accepted for a Linux platform", preflight(decl, host, ["declared-node"])[1] == [node_row])
    node_rows = preflight(decl, host, ["declared-node"])[1]
    refuses("a node artifact with no declaration given", "give a file with --node-file",
            lambda: node_input(decl, node_rows, None))
    refuses("a node declaration nobody registered, named", "no registered node `nope`",
            lambda: node_input(decl, node_rows, "nope"))
    with tempfile.TemporaryDirectory(prefix="wz-package-input-") as input_work:
        work = pathlib.Path(input_work)
        given = work / "slot-answerer.toml"
        given.write_bytes((wz_node.NODES / "slot-answerer.toml").read_bytes())
        refuses("a declaration both named and given as a file", "give one",
                lambda: node_input(decl, node_rows, "slot-answerer", given, work))
        refuses("a declaration file when no artifact takes one", "--node-file names a node declaration",
                lambda: node_input(decl, preflight(decl, host, ["capi-pico"])[1], None, given, work))
        refuses("a declaration file that is not there", "no such file",
                lambda: node_input(decl, node_rows, None, work / "absent.toml", work))
        broken = work / "broken" / "slot-answerer.toml"
        broken.parent.mkdir()
        broken.write_bytes(given.read_bytes().replace(b"schema = 1\n", b""))
        refuses("a declaration file that does not validate", "schema is None",
                lambda: node_input(decl, node_rows, None, broken, work))
        from_file = node_input(decl, node_rows, None, given, work)
        expect("a declaration given as a file is the input, identified by the digest of its bytes",
               from_file["id"] == "slot-answerer"
               and from_file["declaration_sha256"] == hashlib.sha256(given.read_bytes()).hexdigest()
               and from_file["generated"].parent == work)
    refuses("a node declaration named when no artifact takes one", "none of the artifacts",
            lambda: node_input(decl, preflight(decl, host, ["capi-pico"])[1], "slot-answerer"))
    expect("no declaration is no input when no artifact takes one",
           node_input(decl, preflight(decl, host, ["capi-pico"])[1], None) is None)
    expect("the registered declaration is the input of a node artifact",
           node_input(decl, node_rows, "slot-answerer")["id"] == "slot-answerer")
    expect("a node build runs the manifest's binary with the declaration's features",
           cargo_argv(platform, False, node_row, "release", None, view)[:9]
           == ["cargo", "build", "--manifest-path", str(ROOT / node_row["manifest"]), "--bin", "declared-node",
               "--features", "declared", "--message-format=json-render-diagnostics"]
           and "-p" not in cargo_argv(platform, False, node_row, "release", None, view))

    lacking = copy.deepcopy(decl)
    for p in lacking["platforms"]:
        if p["id"] == host:
            p["os_provides"] = [f for f in p["os_provides"] if f != "multicast"]
    lack_platform = next(p for p in lacking["platforms"] if p["id"] == host)
    refuses("a capability asking for a facility the platform lacks", "multicast (asked by multicast-transport",
            lambda: artifact_entry(lacking, lack_platform, pico, "lib/libwz_capi_pico.so", pico_blob,
                                   ["multicast-transport"]))
    refuses("a runtime feature asking for a facility the platform lacks",
            "multicast, which platform linux-x86_64-glibc does not provide (asked by wz-runtime-tokio/scouting-active, "
            "wz-runtime-tokio/transport-multicast)",
            lambda: artifact_entry(lacking, lack_platform, demo, "bin/wz-ap-demo", demo_blob, demo_features,
                                   demo_resolved))
    no_iface = copy.deepcopy(decl)
    for p in no_iface["platforms"]:
        if p["id"] == host:
            p["os_provides"] = [f for f in p["os_provides"] if f != "interface-list"]
    refuses("a platform with no interface listing cannot take a host build at all", "(asked by base",
            lambda: artifact_entry(no_iface, next(p for p in no_iface["platforms"] if p["id"] == host), demo,
                                   "bin/wz-ap-demo", demo_blob, demo_features, demo_resolved))
    expect("the same build is accepted where the platform gives the facility",
           artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so", pico_blob, ["multicast-transport"])
           ["device_requires"] is not None)

    # A registered profile as an input (T13).
    view = {"id": "p-query", "base": "zenoh-c", "capabilities": ["query"], "limits": {"WZ_LIMIT_X": 7}}
    pico_args = profile_cargo_args(decl, pico, view)
    expect("a profile gives a library no default features and the graph's features for it",
           pico_args[:2] == ["--no-default-features", "--features"] and "query" in pico_args[2].split(","))
    refuses("a profile on an executable", "an executable has no such mapping",
            lambda: profile_cargo_args(decl, demo, view))
    wanted = sorted(wz_config.features_for(decl, "pico", {"query"}))
    on_view = artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so", pico_blob, wanted)
    expect("a library built with what the profile asks has no profile finding",
           profile_findings(decl, view, [on_view]) == [])
    short = artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so", pico_blob,
                           [f for f in wanted if f != "query"])
    expect("a library lacking a feature the profile asks for is a finding",
           any("lacks the feature `query`" in f for f in profile_findings(decl, view, [short])))
    extra = artifact_entry(decl, platform, pico, "lib/libwz_capi_pico.so", pico_blob, [*wanted, "peer"])
    expect("a library with a capability the profile leaves off is a finding",
           any("has the capability `peer`" in f for f in profile_findings(decl, view, [extra])))
    expect("a profile does not apply to an executable's entry",
           any("does not apply" in f for f in profile_findings(
               decl, view, [artifact_entry(decl, platform, demo, "bin/wz-ap-demo", demo_blob, demo_features,
                                           demo_resolved)])))
    with tempfile.TemporaryDirectory(prefix="wz-package-profile-") as work:
        pdir = pathlib.Path(work) / "out"
        (pdir / "lib").mkdir(parents=True)
        (pdir / "lib" / "libwz_capi_pico.so").write_bytes(pico_blob)
        pmanifest = assemble(decl, platform, {"commit": "0" * 40, "tree_clean": True},
                             {"rustc": "rustc 0", "cc": None, "sdk": None}, [on_view], view)
        expect("a manifest that names a profile has the profile's keys", shape_findings(pmanifest) == [])
        (pdir / MANIFEST_NAME).write_text(render(pmanifest), encoding="utf-8")
        same = lambda _d, _i: copy.deepcopy(view)  # noqa: E731
        expect("a directory built under a profile verifies against its resolution",
               verify_dir(pdir, decl, same) == [])
        moved = lambda _d, _i: {**view, "capabilities": ["query", "queryable"]}  # noqa: E731
        expect("a profile that now resolves differently is a finding",
               any("differs from what" in f for f in verify_dir(pdir, decl, moved)))

        def gone(_d, _i):
            raise Refusal("no registered profile")

        expect("a profile the tree no longer has is a finding",
               any("profile 'p-query'" in f for f in verify_dir(pdir, decl, gone)))
        data = json.loads((pdir / MANIFEST_NAME).read_text())
        data["profile"]["extra"] = 1
        (pdir / MANIFEST_NAME).write_text(json.dumps(data))
        expect("a profile with an extra key is a shape finding",
               any("profile has the keys" in f for f in verify_dir(pdir, decl, same)))
    if wz_config.kconfiglib_module() is not None:
        real = resolve_profile(decl, "host-client-tcp-query")
        expect("a registered profile resolves strictly to its capabilities",
               "query" in real["capabilities"] and "peer" not in real["capabilities"]
               and real["base"] == "zenoh-c" and real["id"] == "host-client-tcp-query")
        refuses("a profile named by a path", "not the name of a registered profile",
                lambda: resolve_profile(decl, "../configs/profiles/host-client-tcp-query"))
        refuses("a profile nobody registered", "no registered profile", lambda: resolve_profile(decl, "nope"))
        expect("a resolved profile builds the libraries it can",
               profile_cargo_args(decl, next(a for a in decl["artifacts"] if a["id"] == "capi-c"), real)[0]
               == "--no-default-features")
    else:
        print("wz-package selftest: the real-profile arms SKIP, kconfiglib is absent "
              "(scripts/provision-kconfiglib.sh)")

    # Which cross platforms a machine can package.
    env_android = {name: "x" for name in wz_config.toolchain_env(
        next(p for p in decl["platforms"] if p["id"] == "android-arm64"))}
    expect("a cross platform with its toolchain variables set is ready",
           ready_platforms(decl, "x86_64-unknown-linux-gnu", env_android) == ["android-arm64"])
    expect("a cross platform with one variable missing is not ready",
           ready_platforms(decl, "x86_64-unknown-linux-gnu",
                           {k: v for k, v in env_android.items() if k != "AR_aarch64_linux_android"}) == [])
    expect("nothing is ready with no variables", ready_platforms(decl, "x86_64-unknown-linux-gnu", {}) == [])
    expect("the host's own triple is never a cross platform",
           "linux-x86_64-glibc" not in ready_platforms(decl, "x86_64-unknown-linux-gnu", env_android))
    expect("an unassessed platform is never ready, whatever the environment",
           "linux-aarch64-glibc" not in ready_platforms(
               unassessed_decl, "x86_64-unknown-linux-gnu",
               {**env_android, "CC_aarch64_unknown_linux_gnu": "x", "AR_aarch64_unknown_linux_gnu": "x",
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "x"}))
    expect("an assessed platform with its variables set is ready",
           "linux-aarch64-glibc" in ready_platforms(
               decl, "x86_64-unknown-linux-gnu",
               {"CC_aarch64_unknown_linux_gnu": "x", "AR_aarch64_unknown_linux_gnu": "x",
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": "x"}))

    # The SDK identity of a cross build (T2).
    with tempfile.TemporaryDirectory(prefix="wz-ndk-") as ndk:
        root = pathlib.Path(ndk)
        (root / "toolchains" / "llvm" / "bin").mkdir(parents=True)
        (root / "source.properties").write_text("Pkg.Desc = Android NDK\nPkg.Revision = 30.0.1-beta1\n")
        clang = root / "toolchains" / "llvm" / "bin" / "clang"
        clang.write_text("")
        expect("the NDK revision is read from the source.properties above the compiler",
               read_ndk_revision(f"{clang} --target=x") == "30.0.1-beta1")
        expect("a compiler outside any NDK has no revision", read_ndk_revision("/usr/bin/true") is None)
        (root / "source.properties").write_text("Pkg.Desc = Android NDK\n")
        expect("a source.properties with no revision gives none", read_ndk_revision(str(clang)) is None)
        (root / "source.properties").write_text("Pkg.Revision = 30.0.1-beta1\n")
        android = next(p for p in decl["platforms"] if p["id"] == "android-arm64")
        var = "CC_aarch64_linux_android"
        saved_cc = os.environ.get(var)
        os.environ[var] = str(clang)
        try:
            expect("an Android build records the NDK revision and kind only",
                   sdk_identity(android, True) == {"kind": "android-ndk", "revision": "30.0.1-beta1"})
            os.environ[var] = "/usr/bin/true"
            refuses("a compiler outside an NDK", "not inside an NDK", lambda: sdk_identity(android, True))
        finally:
            if saved_cc is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = saved_cc
    qnx_plat = next(p for p in decl["platforms"] if p["id"] == "qnx710-iosock-aarch64")
    demo_row = next(a for a in decl["artifacts"] if a["id"] == "ap-demo")
    expect("a platform with no prebuilt std is built with build-std",
           cargo_argv(qnx_plat, True, demo_row, "release")[-4:]
           == ["--target", qnx_plat["triple"], "-Z", "build-std=std,panic_abort"])
    expect("a platform with a prebuilt std is not",
           "-Z" not in cargo_argv(next(p for p in decl["platforms"] if p["id"] == "android-arm64"),
                                  True, demo_row, "release"))
    expect("a native build is not, whatever its std row says",
           "-Z" not in cargo_argv(qnx_plat, False, demo_row, "release"))
    expect("a native build has no SDK identity", sdk_identity(platform, False) is None)
    refuses("a cross platform that names no sdk kind", "names no sdk_kind",
            lambda: sdk_identity({"id": "x", "triple": "t-1"}, True))
    refuses("an sdk kind the entry cannot read", "cannot read a `gcc` SDK",
            lambda: sdk_identity({"id": "x", "triple": "t-1", "sdk_kind": "gcc"}, True))
    with tempfile.TemporaryDirectory(prefix="wz-qnx-") as qnx:
        sdp = pathlib.Path(qnx)
        (sdp / "target" / "qnx7").mkdir(parents=True)
        meta = sdp / ".packages" / "metadata"
        (meta / "com.qnx.qnx710" / "7.1.0.00472T202006132107S").mkdir(parents=True)
        (meta / "com.qnx.qnx710.target.net.iosock" / "1.0").mkdir(parents=True)
        target = str(sdp / "target" / "qnx7")
        expect("the SDP release is the one directory of the release package, not of a part",
               read_qnx_sdp_release(target) == "7.1.0.00472T202006132107S")
        (meta / "com.qnx.qnx710" / "7.1.1.0").mkdir()
        expect("two releases under one SDP give none", read_qnx_sdp_release(target) is None)
        expect("an empty QNX_TARGET gives none", read_qnx_sdp_release("") is None)
        expect("a target outside any SDP gives none", read_qnx_sdp_release("/usr") is None)
        (meta / "com.qnx.qnx710" / "7.1.1.0").rmdir()
        qnx_row = {"id": "x", "triple": "t-1", "sdk_kind": "qnx-sdp"}
        saved_t = os.environ.get("QNX_TARGET")
        os.environ["QNX_TARGET"] = target
        try:
            expect("a QNX build records the SDP release and kind only",
                   sdk_identity(qnx_row, True) == {"kind": "qnx-sdp", "revision": "7.1.0.00472T202006132107S"})
            os.environ["QNX_TARGET"] = "/usr"
            refuses("a QNX build whose target leads to no release", "exactly one release",
                    lambda: sdk_identity(qnx_row, True))
        finally:
            if saved_t is None:
                os.environ.pop("QNX_TARGET", None)
            else:
                os.environ["QNX_TARGET"] = saved_t
    # The C compiler identity of a cross build. `qcc` answers no `--version`: with a variant selected it
    # answers the preprocessor's macro dump, and that is what a qnx-sdp platform is read by.
    with tempfile.TemporaryDirectory(prefix="wz-qcc-") as fake:
        qcc = pathlib.Path(fake) / "qcc"
        qcc.write_text('#!/bin/sh\ncase "$*" in\n*--version*) exit 1 ;;\n'
                       '*-Vgcc_ntoaarch64le_cxx*-E*) echo \'#define __VERSION__ "8.3.0 test"\' ;;\n*) exit 1 ;;\nesac\n')
        qcc.chmod(0o755)
        silent = pathlib.Path(fake) / "silent"
        silent.write_text("#!/bin/sh\nexit 1\n")
        silent.chmod(0o755)
        qnx_target = {"id": "x", "triple": "aarch64-unknown-nto-qnx710_iosock", "sdk_kind": "qnx-sdp"}
        cc_var = "CC_aarch64_unknown_nto_qnx710_iosock"
        saved_c = os.environ.get(cc_var)
        try:
            os.environ[cc_var] = str(qcc)
            expect("a qnx-sdp compiler that refuses --version is read through the qcc macro dump",
                   cc_identity(qnx_target, True) == "qcc (GCC 8.3.0 test, variant gcc_ntoaarch64le_cxx)")
            os.environ[cc_var] = str(silent)
            refuses("a qnx-sdp compiler that answers neither", "neither --version nor the qcc macro dump",
                    lambda: cc_identity(qnx_target, True))
            os.environ[cc_var] = str(qcc)
            refuses("a compiler of another sdk kind is not read through qcc", "did not answer --version",
                    lambda: cc_identity({**qnx_target, "sdk_kind": "yocto"}, True))
            os.environ["CC_armv7_unknown_nto_qnx710"] = str(qcc)
            refuses("a qnx-sdp architecture with no known qcc variant", "no qcc variant is known",
                    lambda: cc_identity({**qnx_target, "triple": "armv7-unknown-nto-qnx710"}, True))
        finally:
            os.environ.pop("CC_armv7_unknown_nto_qnx710", None)
            if saved_c is None:
                os.environ.pop(cc_var, None)
            else:
                os.environ[cc_var] = saved_c
    yocto_vars = ("OECORE_SDK_VERSION", "OECORE_TARGET_ARCH", "OECORE_TARGET_OS")
    saved_y = {v: os.environ.pop(v) for v in yocto_vars if v in os.environ}
    try:
        refuses("a yocto build with the SDK's variables unset", "OECORE_SDK_VERSION, OECORE_TARGET_ARCH, "
                "OECORE_TARGET_OS is not set", lambda: sdk_identity({"id": "x", "triple": "t-1",
                                                                     "sdk_kind": "yocto"}, True))
        os.environ.update({"OECORE_SDK_VERSION": "4.0.35", "OECORE_TARGET_ARCH": "aarch64",
                           "OECORE_TARGET_OS": "linux"})
        expect("a yocto build records the SDK's values and no path",
               sdk_identity({"id": "x", "triple": "t-1", "sdk_kind": "yocto"}, True)
               == {"kind": "yocto", "revision": "4.0.35", "target_arch": "aarch64", "target_os": "linux"})
    finally:
        for v in yocto_vars:
            os.environ.pop(v, None)
        os.environ.update(saved_y)

    _selftest_bundle(decl, expect, refuses)

    # The fixture corpus: the tracked one is what this entry makes now and is judged as its index says,
    # and the check sees a corpus that drifted, an index that went, and a measured manifest it cannot
    # trust.
    found = fixture_findings(decl)
    expect(f"the tracked fixture corpus is current ({found})", found == [])
    with tempfile.TemporaryDirectory(prefix="wz-package-fixtures-") as fixture_work:
        root = pathlib.Path(fixture_work) / "corpus"
        shutil.copytree(FIXTURES, root)
        drifted = root / "synthetic" / "host-library-and-executable" / "lib" / "libwz_capi_pico.so"
        drifted.write_bytes(_flip_last(drifted.read_bytes()))
        expect("a fixture that is not what the entry makes is reported",
               any("is not what this entry makes now" in f for f in fixture_findings(decl, root)))
        drifted.write_bytes(_flip_last(drifted.read_bytes()))
        (root / FIXTURE_INDEX).unlink()
        expect("a corpus with no index is reported", any("not readable" in f for f in fixture_findings(decl, root)))
        write_fixtures(decl, root)
        expect("writing the corpus again makes it current", fixture_findings(decl, root) == [])
        clean = root / "synthetic" / "host-declared-node"
        record_measured(decl, clean, root)
        expect("a verified package of a committed tree is recorded as measured and indexed",
               (root / "measured" / "linux-x86_64-glibc-slot-answerer.json").is_file()
               and fixture_findings(decl, root) == [])
        refuses("a package that does not verify is not recorded", "does not verify",
                lambda: record_measured(decl, root / "synthetic" / "files-artifact-missing", root))
        dirty = root / "dirty"
        shutil.copytree(clean, dirty)
        data = json.loads((dirty / MANIFEST_NAME).read_text())
        data["built_from"]["tree_clean"] = False
        (dirty / MANIFEST_NAME).write_text(render(data), encoding="utf-8")
        refuses("a package built from uncommitted changes is not recorded", "uncommitted",
                lambda: record_measured(decl, dirty, root))
        measured = root / "measured" / "linux-x86_64-glibc-slot-answerer.json"
        data = json.loads(measured.read_text())
        data["extra"] = 1
        measured.write_text(render(data), encoding="utf-8")
        expect("a measured manifest of another shape is reported",
               any("record it again" in f for f in fixture_findings(decl, root)))

    # The declaration and the stamp gate agree on which families exist.
    import abi_stamp_gate

    expect("every declared family is pinned by the stamp gate and every pinned family is declared",
           {a["family"] for a in decl["artifacts"]} == set(abi_stamp_gate.EXPECTED))
    expect("a file name is derived from the declaration, not a path",
           all("/" not in a["file"] for a in decl["artifacts"]))
    print("wz-package: selftest OK")
    return 0


def _selftest_bundle(decl: dict, expect, refuses) -> None:
    """Bundling (T5): a library a platform bundles is copied from a stand-in SDK, measured, closed
    over what it needs in turn, and re-measured by `--verify`; each defect has a file or a manifest
    whose fault is known, beside the clean package that verifies."""
    host = "linux-x86_64-glibc"
    bdecl = copy.deepcopy(decl)
    platform = next(p for p in bdecl["platforms"] if p["id"] == host)
    # The host row bundles nothing and names no SDK; a copy is given both, so the arms run on files.
    platform["sdk_kind"] = "yocto"
    platform["bundle_from_sdk"] = ["libcxx.so.1", "libcxxabi.so.1"]
    sdk = {"kind": "yocto", "revision": "0", "target_arch": "x86_64", "target_os": "linux"}
    system = [n for n in platform["system_assumed"] if n != "ld-linux-x86-64.so.2"]
    pico = next(a for a in bdecl["artifacts"] if a["id"] == "capi-pico")

    def library(soname: str | None, needed: list[str]) -> bytes:
        return elf_facts.build_test_elf(needed=needed, soname=soname, machine=62,
                                        verneed=[("libc.so.6", ["GLIBC_2.17"])])

    with tempfile.TemporaryDirectory(prefix="wz-package-bundle-") as work:
        root = pathlib.Path(work)
        sdk_dir = root / "sdk"
        sdk_dir.mkdir()
        (sdk_dir / "libcxx.so.1").write_bytes(library("libcxx.so.1", [*system, "libcxxabi.so.1"]))
        (sdk_dir / "libcxxabi.so.1").write_bytes(library("libcxxabi.so.1", system))
        (sdk_dir / "libcxxabi.so.1").chmod(0o444)

        def locate(_platform: dict, soname: str) -> pathlib.Path | None:
            found = sdk_dir / soname
            return found if found.is_file() else None

        pico_blob = _synthetic(pico, [*system, "libcxx.so.1"])
        entry = artifact_entry(bdecl, platform, pico, "lib/libwz_capi_pico.so", pico_blob, ["peer"])
        expect("a NEEDED the platform bundles is `bundled` and names its file",
               entry["elf"]["needed"][-1] == {"soname": "libcxx.so.1", "provided_by": "bundled",
                                              "artifact": "lib/libcxx.so.1"})
        out = root / "out"
        (out / "lib").mkdir(parents=True)
        (out / "lib" / "libwz_capi_pico.so").write_bytes(pico_blob)
        bundled = bundle(platform, [entry], out, locate)
        expect("what a bundled library needs in turn is bundled too, in SONAME order",
               [b["soname"] for b in bundled] == ["libcxx.so.1", "libcxxabi.so.1"])
        expect("a bundled file is the SDK's bytes",
               (out / "lib" / "libcxxabi.so.1").read_bytes() == (sdk_dir / "libcxxabi.so.1").read_bytes())
        expect("a bundled file does not keep the SDK's read-only mode",
               os.access(out / "lib" / "libcxxabi.so.1", os.W_OK))
        manifest = assemble(bdecl, platform, {"commit": "0" * 40, "tree_clean": True},
                            {"rustc": "rustc 0", "cc": None, "sdk": sdk}, [entry], None, bundled)
        expect("the shape of a manifest that bundles is clean", shape_findings(manifest) == [])
        (out / MANIFEST_NAME).write_text(render(manifest), encoding="utf-8")
        expect(f"a package that bundles verifies ({verify_dir(out, bdecl)})", verify_dir(out, bdecl) == [])
        again = root / "again"
        (again / "lib").mkdir(parents=True)
        expect("bundling the same SDK twice gives the same entries",
               bundle(platform, [entry], again, locate) == bundled)

        def found_after(label: str, damage, words: str, dec: dict | None = None) -> None:
            copy_dir = root / "copy"
            if copy_dir.exists():
                shutil.rmtree(copy_dir)
            shutil.copytree(out, copy_dir)
            damage(copy_dir)
            found = verify_dir(copy_dir, dec or bdecl)
            expect(f"{label}: not reported ({found})", any(words in f for f in found))

        def flip(dir_: pathlib.Path) -> None:
            file = dir_ / "lib" / "libcxxabi.so.1"
            data = bytearray(file.read_bytes())
            data[-1] ^= 0xFF
            file.write_bytes(bytes(data))

        def edit(fn):
            def damage(dir_: pathlib.Path) -> None:
                data = json.loads((dir_ / MANIFEST_NAME).read_text())
                fn(data)
                (dir_ / MANIFEST_NAME).write_text(json.dumps(data, indent=2) + "\n")
            return damage

        found_after("a byte of a bundled library changed", flip, "sha256")
        found_after("a bundled library removed", lambda d: (d / "lib" / "libcxxabi.so.1").unlink(), "is missing")
        found_after("a bundled library replaced by one with another SONAME",
                    lambda d: (d / "lib" / "libcxxabi.so.1").write_bytes(library("libother.so.1", system)),
                    "SONAME")
        found_after("a bundled library replaced by one that needs what nobody provides",
                    lambda d: (d / "lib" / "libcxxabi.so.1").write_bytes(
                        library("libcxxabi.so.1", [*system, "libfoo.so.1"])), "libfoo.so.1")
        found_after("a bundled entry removed from the manifest, its file left",
                    edit(lambda m: m["bundled"].pop()), "bundles no libcxxabi.so.1")
        found_after("a bundled entry nothing needs", edit(lambda m: m["artifacts"][0]["elf"]["needed"].pop()),
                    "nothing in the package needs it")
        found_after("bundled entries out of order", edit(lambda m: m["bundled"].reverse()), "SONAME order")
        found_after("a bundled path that leaves the directory",
                    edit(lambda m: m["bundled"][0].__setitem__("path", "../libcxx.so.1")), "inside the directory")
        found_after("a bundle with no SDK named", edit(lambda m: m["toolchain"].__setitem__("sdk", None)),
                    "names no SDK")
        unbundled = copy.deepcopy(bdecl)
        next(p for p in unbundled["platforms"] if p["id"] == host)["bundle_from_sdk"] = ["libcxx.so.1"]
        found_after("a library the platform no longer bundles", lambda d: None,
                    "not a library platform", unbundled)

        refuses("a library the SDK does not have", "does not find it",
                lambda: bundle(platform, [entry], root / "missing-sdk", lambda _p, _s: None))
        (sdk_dir / "libcxx.so.1").write_bytes(library("libcxx.so.2", system))
        refuses("an SDK file that is another library", "SONAME 'libcxx.so.2'",
                lambda: sdk_bundle_check(platform, locate))
        (sdk_dir / "libcxx.so.1").write_bytes(library("libcxx.so.1", [*system, "libfoo.so.1"]))
        refuses("an SDK library that needs what the platform neither assumes nor bundles", "libfoo.so.1",
                lambda: sdk_bundle_check(platform, locate))
        (sdk_dir / "libcxx.so.1").write_bytes(library("libcxx.so.1", [*system, "libcxxabi.so.1"]))
        expect("the lane's check reads every library the platform bundles",
               [line.split(":", 1)[0] for line in sdk_bundle_check(platform, locate)]
               == ["libcxx.so.1", "libcxxabi.so.1"])
        clash = root / "clash"
        (clash / "lib").mkdir(parents=True)
        (clash / "lib" / "libcxx.so.1").write_bytes(b"x")
        refuses("a bundled name an artifact already has", "has that file name",
                lambda: bundle(platform, [entry], clash, locate))
    expect("a platform that bundles nothing is checked as such",
           sdk_bundle_check(next(p for p in decl["platforms"] if p["id"] == host)) == [])

    # Where the SDK's file is: the linker driver's own search directories, in its order. The texts
    # have the shapes the drivers print (an NDK Clang's `-print-search-dirs`, `qcc -v` linking).
    expect("a driver's library directories are its `libraries:` line, in order, once each",
           search_dirs_of("programs: =/p\nlibraries: =/a/36:/a:/b:/a\n") == ["/a/36", "/a", "/b"])
    expect("a driver that states no libraries line states no directory", search_dirs_of("programs: =/p\n") == [])
    qcc_text = ("cc: looking for gcc_ntoaarch64le_cxx in /s/etc/qcc/gcc/8.3.0/gcc_ntoaarch64le_cxx.conf\n"
                "/s/lib/cc1 -quiet -Asystem(unix) -isystem /t/usr/include m.c -o - | \\\n"
                " /s/bin/aarch64-unknown-nto-qnx7.1.0-as -EL -o m.o\n"
                "/s/bin/aarch64-unknown-nto-qnx7.1.0-ld --sysroot=/t/aarch64le/ -rpath-link /t/aarch64le/lib "
                "-Y/t/aarch64le/lib:/t/aarch64le/usr/lib -L/s/gcc -L /t/aarch64le/lib -L/t/aarch64le/usr/lib "
                "-lc -lgcc_s /s/crtend.o\n"
                "cc: unlinking m.o\n")
    expect("qcc's link line gives each -L, then the -Y default path, in the linker's order",
           qcc_link_dirs(qcc_text) == ["/s/gcc", "/t/aarch64le/lib", "/t/aarch64le/usr/lib"])
    expect("a qcc run with no link line states no directory", qcc_link_dirs("cc: no files to process\n") == [])
    with tempfile.TemporaryDirectory(prefix="wz-package-driver-") as work:
        root = pathlib.Path(work)
        (root / "first").mkdir()
        (root / "second").mkdir()
        (root / "second" / "libcxx.so.1").write_bytes(b"x")
        (root / "first" / "libcxxabi.so.1").write_bytes(b"x")
        (root / "second" / "libcxxabi.so.1").write_bytes(b"y")
        driver = root / "driver"
        driver.write_text(f"#!/bin/sh\necho 'libraries: ={root / 'first'}:{root / 'second'}'\n")
        driver.chmod(0o755)
        silent = root / "silent"
        silent.write_text("#!/bin/sh\nexit 0\n")
        silent.chmod(0o755)
        android = next(p for p in decl["platforms"] if p["id"] == "android-arm64")
        variable = f"CARGO_TARGET_{android['triple'].replace('-', '_').upper()}_LINKER"
        saved = os.environ.get(variable)
        try:
            os.environ[variable] = str(driver)
            expect("the SDK's file is found in a later directory when the earlier lacks it",
                   sdk_library(android, "libcxx.so.1") == root / "second" / "libcxx.so.1")
            expect("the first directory that holds the name wins, as in the link",
                   sdk_library(android, "libcxxabi.so.1") == root / "first" / "libcxxabi.so.1")
            expect("a name no directory holds is not found", sdk_library(android, "libnone.so.1") is None)
            os.environ[variable] = str(silent)
            refuses("a linker that states no search directory", "did not state the directories",
                    lambda: sdk_library(android, "libcxx.so.1"))
            os.environ.pop(variable)
            refuses("no linker named", "is not set", lambda: sdk_library(android, "libcxx.so.1"))
        finally:
            os.environ.pop(variable, None)
            if saved is not None:
                os.environ[variable] = saved


def ready_platforms(decl: dict, host: str, environ: dict[str, str]) -> list[str]:
    """The cross platforms this machine can package: assessed rows whose triple is not the
    compiler's host and whose toolchain variables are all set in `environ`.

    The lane runs exactly these, so a platform joins it by being declared and having its toolchain
    provided, not by an edit to the lane; an unset variable is "not provisioned here", which the
    lane reports and (when it is told the platform is required) fails.
    """
    out = []
    for p in decl["platforms"]:
        if "os_provides" not in p or "system_assumed" not in p or p["triple"] == host:
            continue
        if all(environ.get(name) for name in wz_config.toolchain_env(p)):
            out.append(p["id"])
    return out


def main(argv: list[str]) -> int:
    if argv in (["--ready"], ["--required-platforms"]):
        decl = wz_config.load_decl()
        host = rustc_identity()[1]
        if argv == ["--ready"]:
            print("\n".join(ready_platforms(decl, host, dict(os.environ))))
        else:
            print("\n".join(p["id"] for p in decl["platforms"]
                            if p["lane"] != "none" and "os_provides" in p and p["triple"] != host))
        return 0
    if len(argv) == 2 and argv[0] == "--lane-plan":
        try:
            plain, nodes = lane_plan(wz_config.load_decl(), argv[1])
        except Refusal as err:
            print(f"wz-package: REFUSED -- {err}", file=sys.stderr)
            return 2
        print("\n".join([f"artifact {a}" for a in plain] + [f"node {n}" for n in nodes]))
        return 0
    if len(argv) == 2 and argv[0] == "--sdk-bundle-check":
        decl = wz_config.load_decl()
        platform = next((p for p in decl["platforms"] if p["id"] == argv[1]), None)
        try:
            if platform is None:
                raise Refusal(f"no platform `{argv[1]}` is declared")
            if platform.get("bundle_from_sdk"):
                check_toolchain_env(platform, True)
            lines = sdk_bundle_check(platform)
        except (Refusal, elf_facts.ElfError) as err:
            print(f"wz-package: REFUSED -- {err}", file=sys.stderr)
            return 2
        for line in lines or ["bundles nothing from its SDK"]:
            print(f"  wz-package: {argv[1]}: {line}")
        return 0
    if argv in (["--write-fixtures"], ["--check-fixtures"]) or (len(argv) == 2 and argv[0] == "--record-measured"):
        decl = wz_config.load_decl()
        if argv == ["--write-fixtures"]:
            return write_fixtures(decl)
        if argv == ["--check-fixtures"]:
            findings = fixture_findings(decl)
            for finding in findings:
                print(f"  wz-package FAIL: {finding}", file=sys.stderr)
            if not findings:
                print("  wz-package: the fixture corpus is current and judged as its index says")
            return 1 if findings else 0
        try:
            return record_measured(decl, pathlib.Path(argv[1]))
        except Refusal as err:
            print(f"wz-package: REFUSED -- {err}", file=sys.stderr)
            return 2
    if argv == ["--selftest"]:
        try:
            return _selftest()
        except AssertionError as err:
            print(f"wz-package: FAIL -- {err}", file=sys.stderr)
            return 1
    decl = wz_config.load_decl()
    if len(argv) == 2 and argv[0] == "--verify":
        findings = verify_dir(pathlib.Path(argv[1]), decl)
        for finding in findings:
            print(f"  wz-package FAIL: {finding}", file=sys.stderr)
        if not findings:
            print(f"  wz-package: {argv[1]} verifies")
        return 1 if findings else 0
    platform_id = out = profile_id = node_id = None
    node_file: pathlib.Path | None = None
    artifact_ids: list[str] = []
    cargo_profile = "release"
    it = iter(argv)
    for arg in it:
        if arg == "--platform":
            platform_id = next(it, None)
        elif arg == "--artifact":
            artifact_ids.append(next(it, ""))
        elif arg == "--out":
            out = next(it, None)
        elif arg == "--cargo-profile":
            cargo_profile = next(it, "")
        elif arg == "--profile":
            profile_id = next(it, None)
        elif arg == "--node":
            node_id = next(it, None)
        elif arg == "--node-file":
            node_file = pathlib.Path(next(it, ""))
        else:
            print(f"wz-package: unknown argument {arg}", file=sys.stderr)
            return 2
    if not platform_id or not artifact_ids or not out or cargo_profile not in ("release", "debug"):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return 2
    try:
        return package(decl, platform_id, artifact_ids, pathlib.Path(out), cargo_profile, profile_id, node_id,
                       node_file)
    except Refusal as err:
        print(f"wz-package: REFUSED -- {err}", file=sys.stderr)
        return 2
    except (RuntimeError, elf_facts.ElfError) as err:
        print(f"wz-package: FAIL -- {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
