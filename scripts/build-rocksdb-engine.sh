#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
# R2805: keep the native engine outside Cargo's per-feature build directories.
# Uses the checksum-pinned source shipped by librocksdb-sys, with all five
# codecs: the wz workspace and the upstream filesystem oracle enable different
# codec sets. A shared library carries its codec dependencies for both callers.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$root/scripts/lib/rocksdb_engine.py" "$@"
