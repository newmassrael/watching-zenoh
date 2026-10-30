#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R2575 (no register item) -- the same owner decision (2026-09-12, grow the
# environment for oracle-blocked atoms) that `netns-topology.sh` answers; this is
# its second way of holding the privilege, for a host with no sudo.
#
# Run a command inside the namespace sandbox of `netns-topology.sh`
# (`netns_sandbox_exec`): the prefix a lane puts before a witness that builds a
# network namespace when the host gives it no sudo.
#
#     bash scripts/lib/netns-sandbox.sh cargo test -p wz-integration-tests ...
#
# A lane learns whether it needs this from `netns_topology_probe`, which answers
# 3 for "available, but only inside the sandbox". The decision is the lane's;
# this file only runs what it is given.

# shellcheck source=scripts/lib/netns-topology.sh
source "$(dirname "${BASH_SOURCE[0]}")/netns-topology.sh" || exit 4
netns_sandbox_exec "$@"
