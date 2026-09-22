#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2805: provision the locked RocksDB source once, outside Cargo feature units.

Only Linux native CI opts in. Normal developer and cross builds keep the crate's
own build. Cache identity includes the source checksum, recipe, host and compiler;
restores verify the library digest and run a C++ version/codec probe before export.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CODECS = ("SNAPPY", "LZ4", "ZLIB", "ZSTD", "BZ2")


def run(*args: str, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def locked_engine(lock: Path) -> tuple[str, str]:
    blocks = [b for b in lock.read_text().split("[[package]]")
              if re.search(r'^name = "librocksdb-sys"$', b, re.M)]
    if len(blocks) != 1:
        raise ValueError(f"{lock}: expected one librocksdb-sys")
    def field(name):
        match = re.search(rf'^{name} = "([^"]+)"$', blocks[0], re.M)
        if not match:
            raise ValueError(f"{lock}: missing {name}")
        return match[1]
    version, checksum = field("version"), field("checksum")
    if not re.fullmatch(r"[0-9.]+\+[0-9.]+", version) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("unexpected engine version or checksum")
    return version, checksum


def identity() -> dict:
    version, checksum = locked_engine(ROOT / "crates/Cargo.lock")
    if locked_engine(ROOT / "oracles/Cargo.lock") != (version, checksum):
        raise ValueError("workspace and upstream oracle need different engines")
    if platform.system() != "Linux":
        raise ValueError("the shared engine is only provisioned for native Linux")
    return dict(version=version, checksum=checksum, arch=platform.machine(),
                os=Path("/etc/os-release").read_text(),
                compiler=subprocess.check_output(["c++", "--version"], text=True),
                recipe=digest(Path(__file__)), wrapper=digest(ROOT / "scripts/build-rocksdb-engine.sh"))


def probe(out: Path, version: str) -> None:
    # Query the loaded engine, not just its filename. Every codec must survive
    # a real flush/read; this also exercises the dependencies after a restore.
    source = r'''
#include <rocksdb/db.h>
#include <rocksdb/version.h>
#include <iostream>
int main(int argc, char** argv) {
  if (argc != 3 || rocksdb::GetRocksVersionAsString() != argv[1]) return 1;
  for (auto codec : {rocksdb::kSnappyCompression, rocksdb::kZlibCompression,
                    rocksdb::kBZip2Compression, rocksdb::kLZ4Compression,
                    rocksdb::kZSTD}) {
    rocksdb::Options options;
    options.create_if_missing = true;
    options.compression = codec;
    std::string path = std::string(argv[2]) + "/" + std::to_string(codec);
    rocksdb::DB* db = nullptr;
    auto status = rocksdb::DB::Open(options, path, &db);
    if (!status.ok()) { std::cerr << status.ToString(); return 2; }
    std::string value(65536, 'x'), got;
    status = db->Put(rocksdb::WriteOptions(), "probe", value);
    if (status.ok()) status = db->Flush(rocksdb::FlushOptions());
    delete db;
    if (!status.ok()) { std::cerr << status.ToString(); return 3; }
    status = rocksdb::DB::Open(options, path, &db);
    if (!status.ok()) { std::cerr << status.ToString(); return 4; }
    status = db->Get(rocksdb::ReadOptions(), "probe", &got);
    delete db;
    if (!status.ok() || got != value) return 5;
  }
}
'''
    with tempfile.TemporaryDirectory(prefix="wz-rocksdb-probe-") as temp:
        p = Path(temp)
        (p / "probe.cc").write_text(source)
        run("c++", "-std=c++17", str(p / "probe.cc"), f"-I{out / 'include'}",
            f"-L{out / 'lib'}", f"-Wl,-rpath,{out / 'lib'}", "-lrocksdb", "-pthread",
            "-o", str(p / "probe"))
        run(str(p / "probe"), version.split("+")[1], temp)


def valid(out: Path, expected: dict) -> bool:
    try:
        saved = json.loads((out / "engine.json").read_text())
        return (saved["identity"] == expected and
                saved["library_sha256"] == digest(out / "lib/librocksdb.so"))
    except (OSError, ValueError, KeyError):
        return False


def build(out: Path, expected: dict, jobs: int) -> None:
    # Build in a sibling staging directory: an interrupted compile cannot leave
    # a cache entry that appears complete. Source is authenticated before unpack.
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".rocksdb-build-", dir=out.parent) as temp:
        work = Path(temp)
        archive = work / "source.crate"
        version = expected["version"]
        run("curl", "--fail", "--location", "--retry", "3", "--max-time", "180",
            f"https://static.crates.io/crates/librocksdb-sys/librocksdb-sys-{version}.crate",
            "--output", str(archive))
        if digest(archive) != expected["checksum"]:
            raise ValueError("librocksdb-sys archive does not match Cargo.lock")
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if (Path(member.name).is_absolute() or ".." in Path(member.name).parts
                        or not (member.isfile() or member.isdir())):
                    raise ValueError("unexpected archive member")
            tar.extractall(work)
        src = work / f"librocksdb-sys-{version}" / "rocksdb"
        obj, stage = work / "build", work / "install"
        run("cmake", "-S", str(src), "-B", str(obj), "-DCMAKE_BUILD_TYPE=Release",
            "-DPORTABLE=ON", "-DROCKSDB_BUILD_SHARED=ON", "-DWITH_GFLAGS=OFF",
            "-DWITH_LIBURING=OFF", "-DWITH_TESTS=OFF", "-DWITH_TOOLS=OFF",
            "-DWITH_CORE_TOOLS=OFF", "-DWITH_BENCHMARK_TOOLS=OFF",
            "-DFAIL_ON_WARNINGS=OFF", *[f"-DWITH_{c}=ON" for c in CODECS])
        run("cmake", "--build", str(obj), "--target", "rocksdb-shared", "--parallel", str(jobs))
        (stage / "lib").mkdir(parents=True)
        shutil.copytree(src / "include", stage / "include")
        for library in obj.glob("librocksdb.so*"):
            shutil.copy2(library, stage / "lib" / library.name, follow_symlinks=False)
        probe(stage, version)
        (stage / "engine.json").write_text(json.dumps(dict(
            identity=expected, library_sha256=digest(stage / "lib/librocksdb.so")), indent=2))
        if out.exists():
            shutil.rmtree(out)
        stage.rename(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", action="store_true", help="print the source/recipe/compiler cache key")
    parser.add_argument("--verify", action="store_true", help="verify without rebuilding or exporting")
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 2, 4))
    args = parser.parse_args()
    expected = identity()
    key = hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()
    if args.key:
        print(key)
        return
    out = ROOT / "target/rocksdb-engine" / key
    if not valid(out, expected):
        if args.verify:
            raise ValueError("engine cache absent, stale or corrupt")
        if args.jobs < 1:
            raise ValueError("--jobs must be positive")
        build(out, expected, args.jobs)
    probe(out, expected["version"])
    if args.verify:
        print("rocksdb-engine: version and all five codecs verified")
        return
    # An inherited STATIC/COMPILE flag would override the shared library path.
    for name in ("ROCKSDB_STATIC", "ROCKSDB_COMPILE", "ROCKSDB_INCLUDE_DIR"):
        if name in os.environ:
            raise ValueError(f"unset {name} before selecting the CI engine")
    env = f"ROCKSDB_LIB_DIR={out / 'lib'}\nLD_LIBRARY_PATH={out / 'lib'}"
    if os.environ.get("LD_LIBRARY_PATH"):
        env += ":" + os.environ["LD_LIBRARY_PATH"]
    env += "\n"
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a") as file:
            file.write(env)
    print(env, end="")


if __name__ == "__main__":
    main()
