<!--
SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->

# deploy/

Canonical deploy.yaml skeletons that pin the per-target build
parameters for each deploy class. The same `sources/` SCXML pool
emits to different backend + runtime combinations driven by these
skeletons; values that differ per target (cache line size,
cooperative budget, link kind) live here so the SCXML stays
target-agnostic.

## Deploy classes

| File | Target | Runtime | Phase |
|---|---|---|---|
| ap_standalone.yaml | AP-only (x86_64 Linux) | `wz-runtime-tokio` (mio epoll, io_uring opt-in) | D.1 (pending Phase C closure) |
| mcu_target.yaml | MCU-only (STM32H747 Cortex-M7) | `wz-runtime-coop` (cooperative scheduler) | A–C track (zenoh-pico parity) |
| ap_mcu_pair.yaml | Hybrid AP + MCU | Both runtimes paired | D.1 + A–C |
| mcu_client_and_group.yaml | MCU, FreeRTOS heap profile, two sessions | `wz-runtime-freertos` (coop executor in one task) | open-debt item 900 |

Each skeleton's header comment lists the resolved
`rfc-open-questions-log.md` answers (OQ-W6 / W8 / W12 / W13 /
W17 / W18 / W19 for the MCU side; W6 / W8 / W12 / W13 / W19 for
the AP side) and the RFC §5.K platform block fields.

## Validation

`scripts/validate-deploy.sh` does a lightweight schema check
(YAML well-formedness + top-level `machines:` key + per-machine
required fields) and runs in Layer D of the local CI. The
end-to-end `sce-codegen build deploy/<x>.yaml` exercise is a
known carry — it requires SCE upstream's `build` subcommand,
tracked under R50 / R123b in the atomic changelog.

## Several sessions on one machine

A machine may hold several local sessions, declared as a
`sessions:` list (see `mcu_client_and_group.yaml`). A machine
without the key is a single-session machine as before.
`scripts/lib/deploy_sessions.py` documents every key and
validates it; a refusal names the key, as a dotted path. In short:

- `zid` on the machine is the default every session inherits; a
  session's own `zid` overrides it. Two sessions may share an id
  only when their transports differ (one unicast, one multicast).
- Each session has one `transport` and one `link`, and a link
  carries one session.
- A unicast session takes `connect.endpoints`, `listen.endpoints`
  and `accept.max_sessions`; on an MCU or Zephyr machine only 1
  accepted session is supported.
- A multicast session is a `peer` and takes `group.endpoint`, with
  the interface only as the `#iface=<name|addr>` tail. No tail
  means the first non-loopback multicast interface; `auto` is not
  a word on a locator. On an MCU the tail is honoured only when
  the link declares the same `netif:`.
- `limits` overrides the machine's limits for one session.
- `buffer_pools` are the session's own static pools. Omitted, the
  profile's default pools stand, one instance per session: two
  sessions double that SRAM, and the multicast receive pool alone
  is 32 x 1536 bytes.
- The heap profiles have no per-session heap budget: every session
  allocates from the one image heap. `heap_budget_bytes` is
  reserved and refused.

## Editing

Author-side edits land directly in these files. Every numeric
default is annotated with its derivation (zenoh-pico precedent
or empirical measurement); revisions should preserve the
annotation so future readers can trace why each number is what
it is.
