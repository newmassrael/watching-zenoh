#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
# R2805: keep the native engine outside Cargo's per-feature build directories.
# Uses the checksum-pinned source shipped by librocksdb-sys, with all five
# codecs. The engine is the wz workspace's (crates/Cargo.lock); the upstream
# filesystem oracle builds upstream's own engine (see rocksdb_engine.py).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/scripts/lib/rocksdb_engine.py" "$@"
