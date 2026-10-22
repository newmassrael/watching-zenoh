# Build configuration: one declaration, upstream originals, profiles and presets

Status: design note. It states what exists, what is decided and in what order the
work goes; it is not a specification and the atomic store does not parse it. Every
decision here was taken on the standing criterion of this tree: the long-term
correct structure, cost not counted. It continues `storage-policy-and-link-layer.md`
(D1 storage policy, D4 role as a composition, D5 resource gates) and is the design
for two carries `feature_inventory.md` left open: §7 (how cargo features are
emitted) and §4 (the `inspect` tool).

## 1. The question

The owner's directive is that every wz build, AP, C and pico alike, is configured
from Kconfig and from SCE: any feature on or off, heap or no heap, and an upstream
original reproduced by naming it. Three things follow from it:

1. Choosing "zenoh", "zenoh-c" or "zenoh-pico" is one line, and the build that line
   produces behaves as that original does.
2. A build is customised from an original by turning switches one at a time, up to
   a combination the original never shipped (for example the pico C ABI on a
   fixed-memory MCU image).
3. A user composes such a configuration in a menu, saves it, and gets the same build
   back later, or a refusal when the catalogue it was saved against has moved.

## 2. What exists

- **Capabilities of the C ABI builds** (`deploy/capabilities.toml`): twenty-one, all
  on by default. Two of them change the layout of structs a pico program allocates, so
  a program links the build of the header arm it compiled against: `multi-thread` (off
  is pico's single-threaded C ABI) and `unstable-api` (off is the option layout of
  upstream's default header). They are generated into `deploy/Kconfig.capabilities` and cargo arguments by
  `scripts/lib/capability_config.py`, which also holds the three capi manifests to
  the declared graph. No Kconfig `rsource`s the generated file; the MCU images do
  not see it.
- **Limits** (`crates/wz-session-core/src/caps.rs`): every capacity is
  `limit(option_env!("WZ_LIMIT_<NAME>"), default)`; `deploy/Kconfig.limits` is
  derived from those rows by `scripts/lib/limit_config.py`, and the Zephyr build
  turns each `CONFIG_WZ_LIMIT_*` into the cargo environment
  (`deploy/zephyr-common/wz_zephyr_board.cmake`). `limit()` reads a decimal `usize`
  only.
- **The MCU images' own Kconfig** (`deploy/zephyr-admin-node/Kconfig`): the role
  choice, the network backend choice and `WZ_FIXED_MEMORY`, whose `depends on` is
  written by hand; the mapping from `CONFIG_*` to cargo features is written by hand
  in each image's `CMakeLists.txt`.
- **Storage policy** (D1 step 6, landed): `trait Storage` with `Heap` and `Static`
  (`bounded.rs`), associated types for the sequence, the text, the arena offset,
  the id table and the change epoch; the registries are generic over it and one
  test body runs on both (`tests/storage_policy_tables.rs`). The default policy
  `Profile` is still chosen by the `bounded-heapless` feature.
- **Cost gate** (`scripts/lib/capability_cost_gate.py`): per case, a text budget,
  the absence of the planes a case left out and the presence of those it put in.
- **Upstream switch sets at the pins**, each judged switch by switch:
  `upstream_feature_census.py` for the `zenoh` crate's cargo features, and
  `upstream_switch_map.py` for zenoh-pico's 38 `Z_FEATURE_*` switches and zenoh-c's
  17 cargo features. The relation is not one to one: pico's advanced publication
  and subscription switches are one wz plane, and pico's liveliness get needs two of
  its switches where wz has one capability. The `pico_flag` of
  `deploy/capabilities.toml` names one switch per capability and is held to the map.
- **No Rust API compatibility atom.** `api-compat-c` and `api-compat-pico` exist;
  nothing makes wz a drop-in for the `zenoh` crate's public API.
- **No Kconfig interpreter on the host.** `kconfiglib` exists only inside the
  Zephyr tree.

## 3. The model

A build's configuration is five layers of values; a lower layer may depend on an
upper one, never the reverse.

| Layer | What it is | Kconfig | Reaches the code as |
|---|---|---|---|
| axis | `family` (zenoh, zenoh-c, zenoh-pico), `target`, `role` (client, peer, router), `storage` (heap, static), `exec` (one cooperative task, or the separate read and lease tasks pico runs under `Z_FEATURE_MULTI_THREAD`) | choice | the concrete types the image names |
| capability | a surface upstream also has; on, code is added | bool | an additive cargo feature |
| policy | behaviour beyond upstream; on, behaviour changes | bool / choice | a typed config value, or a strategy type |
| limit | a capacity | int | a const generic argument |
| preset | the values that differ from the defaults | a defconfig fragment | through the layers above |

## 4. Decisions

**C1. One declaration; everything else is generated.** `deploy/wz-config.toml` with
its schema holds the four kinds (axis, capability, policy, limit): id, type and
range, default per `family`, `requires` (axis conditions), `implies`, targets,
exported ABIs, upstream counterpart, help, `since`, plus `catalog_version` and a
`renamed` table. Generated from it, each held by `--check`: the Kconfig tree, the
upstream defconfigs, the Zephyr CMake bridge, the Rust constant modules the limits
and policy defaults are read from, and a catalogue table in `docs/`. Cargo
`[features]` cannot include fragments, so the capi manifests stay cross-checked
against the declaration as they are today. Rejected: three sources joined by
cross-checks (a check finds a drift after it happened; generation leaves nothing to
drift), and the Kconfig language as the source (it has no place for the ABI, the
upstream counterpart or the cargo mapping).

**C2. Three kinds of switch.** A capability defaults to what its `family`'s
original turns on. A policy defaults to upstream's behaviour, always; the generator
refuses an upstream defconfig in which any policy is on. An axis is a choice.

**C3. Cargo features only add code.** Features unify across the graph and cargo
is designed on the premise that they are additive; a switch that changes behaviour
or swaps code is therefore never a feature. A value-only policy is a typed field
of a config struct whose `Default` reads a generated constant (`WZ_POLICY_<NAME>`),
so an image takes the Kconfig value and a test injects both values in one binary.
A policy or an axis that changes the shape of the code is a type parameter (a
strategy trait), monomorphised at no run-time cost. Three non-additive features
exist: `bounded-heapless` and `session-slot` are removed by step 7 below, and
`zenoh-c-no-unstable-api` (which removes the unstable C surface) becomes the value
of the zenoh-c `unstable` switch when the C ABI is generated from its definition
(C12). No new one is admitted, and `--check` says so.

**C4. Capacity is a property of the table.** Every bounded table type takes its
own `const N`, defaulting to the `caps.rs` constant, so existing names keep their
meaning and an image can size two instances differently. The concrete types of an
image are emitted by the generator from its Kconfig values. A single capacity
bundle trait (`C::MAX_*`) is rejected because a generic associated constant cannot
be an array length on stable Rust. This supersedes the "type parameter is YAGNI"
note at the top of `caps.rs`.

**C5. The policy of an image is named, not defaulted by a feature.** The host
runtime names `Heap`, the MCU crates name `Static`, and the generated concrete
types name the choice of an image; `Profile`'s feature-selected default goes.

**C6. Where a capability is possible is declared.** `requires` becomes Kconfig
`depends on`; an impossible combination cannot be selected in the menu rather than
failing in the build.

**C7. Upstream defconfigs come from a complete map.** Each upstream switch is
classified `maps` (a wz switch), `always` (always on in wz), `never` (absent; a debt
row) or `n/a` (with the reason). The gate derives the upstream set from the pinned
upstream source (pico's `CMakeLists.txt`, zenoh's and zenoh-c's `Cargo.toml`) and
fails on an unclassified switch and on a classified one upstream does not have.

**C8. Test unit.** Every switch lands with an on and an off image: a cost-gate case
for a capability, a pair of behaviour tests for a policy, fill-to-N and
refuse-at-N+1 for a limit. Every registered profile builds and runs the interop
lanes. The full product of switches is not tested.

**C9. A saved preset is re-validated strictly.** An unknown symbol, a value whose
`depends on` does not hold and an out-of-range integer are errors, not warnings. A
preset records the catalogue version; a renamed symbol is migrated through
`renamed`, and one that cannot be is refused.

**C10. Drop-in and extension are separate namespaces.** A drop-in header (pico,
zenoh-c) and the Rust compatibility crate carry only upstream's symbols. A wz-only
door is `wz_ext_*` in `wz_ext.h`, and in Rust `wz::ext`. A gate holds each drop-in
header's symbol set to a subset of its upstream header's.

**C11. One pinned Kconfig interpreter.** `kconfiglib` is pinned by version and hash.
The Zephyr build uses the copy Zephyr ships; a CI gate checks that both produce the
same `.config` from the same tree and inputs (the upstream defconfigs and every
registered profile). A third interpreter written in Rust is rejected.

**C12. The C ABI is three layers.** One `no_std` ABI definition crate (value types,
handle tables, error codes, the meaning of each door) from which the headers are
generated and which the ABI pins read; a driver trait implemented by the host
runtime and by the MCU slot host; thin artefact crates (host cdylib, MCU staticlib)
that bind one definition to one driver. The header generator is chosen by whether
it reproduces today's headers byte for byte, with every difference explained.

**C13. `family = zenoh` includes the Rust public API.** Replacing zenoh for a Rust
user means changing a dependency and nothing else; wire, behaviour and API must all
match. A compatibility crate exposes the pinned zenoh's public API over wz, held by
a surface gate derived from the upstream crate's rustdoc JSON.

**C14. Profiles are contracts.** A registered profile is a named, semver-versioned
defconfig fragment that CI builds and tests; its name describes its axes (for
example `mcu-zephyr-static`). User presets live outside the repository and merge
after it.

## 5. Switches

The catalogue is the declaration itself (C1); this note does not keep a second list.
What it fixes is how a switch enters it.

**Capabilities first come from upstream.** The upstream map (C7) is the source of the
capabilities to build: every upstream switch classified `never` is a capability wz
owes, filed as a debt row. The first ones visible today are upstream surfaces wz has
on one target and not another: stream links on MCU, multicast transport in the C
ABI, timestamps on MCU, the advanced publisher and subscriber on the fixed-memory
policy, and the bounded form of the receive match cache (pico's
`Z_FEATURE_RX_CACHE`).

**A policy enters one at a time, with its own case.** A policy is behaviour upstream
does not have. Each is added in its own change, whose message and help text state
what upstream does, what the policy does instead and why a deployment needs it; its
default is upstream's behaviour (C2), and it lands with the pair of behaviour tests
of C8. A policy that cannot state the upstream behaviour it departs from is not a
policy but a capability or a defect.

**One departure exists already.** wz turns multicast loopback on for every socket it
binds (`wz-runtime-tokio/src/lib.rs`, `McastPlan::loop_back`) where upstream leaves
the operating system's default; the same-host tests and the self-echo gate rely on
it. It becomes the first policy, `multicast-loopback` (`os-default` / `on` /
`off`), defaulting to upstream, and those tests name `on`.

## 6. Upstream originals, profiles, presets

```
configs/zenoh_defconfig        family=zenoh      target=host-linux role=peer   storage=heap
configs/zenoh-c_defconfig      family=zenoh-c    target=host-linux role=peer   storage=heap
configs/zenoh-pico_defconfig   family=zenoh-pico target=host-linux role=client storage=heap
configs/zenoh-pico-mcu_defconfig family=zenoh-pico target=mcu-zephyr role=client
configs/profiles/*.conf        registered profiles (C14)
```

An upstream defconfig is that original's own defaults: for zenoh-pico, the values
its `CMakeLists.txt` sets. wz's pico interop lanes compare against a reference build
configured differently (`scripts/build-zenoh-pico-cli.sh`: the unstable API, the
advanced publication and subscription, serial, TLS and connectivity on), and the
pico drop-in's struct layouts are fixed to that build today. That configuration
becomes a registered profile of its own, and producing both layouts, the upstream
default and the reference, is the C ABI generation of C12 (open-debt items 917 and
918 carry the two arms the drop-in cannot produce yet).

`wz-config` is the user's tool: `new <name> --from <original>`, `menu` (menuconfig,
`--gui` for guiconfig), `save` (savedefconfig), `show [--resolved]`, `diff`,
`check` (C9 plus the cost budget of the switches on), `build` (cargo arguments on
the host, `EXTRA_CONF_FILE` on Zephyr) and `inspect` (the switches on and what they
cost). Merge order: upstream defconfig, then a registered profile, then the user's
fragment. A preset file starts with `# wz-preset: 1`, `# catalog: <version>` and
`# base: <original>`, followed by the lines that differ from the defaults.

## 7. Steps

Each step lands with its own done-when; sizes are not estimated here.

1. **One declaration and its generator** (C1, C2, C3, C6, C10, C11). Move the twenty-one
   capabilities, the limits and the axis-like symbols of the MCU images into
   `deploy/wz-config.toml`; the generator absorbs `capability_config.py` and
   `limit_config.py`; the images use the generated Kconfig and CMake bridge; place
   `wz_ext.h` and the subset gate; pin `kconfiglib` and add the equivalence gate.
   Done when the existing images build with the same features and environment as
   before (the cargo command lines compared) and the Layer C0 checks pass on the
   generator.
2. **The upstream map and the upstream defconfigs** (C7). Done when the gate passes
   on the pinned sources and each upstream defconfig's host build passes its interop
   lane (pico C programs, zenoh-c examples, zenohd).
3. **Switches on the existing structure**, one at a time, each by C8 and section 5:
   `multicast-loopback` first.
4. **Role as a composition** (D4). The role axis pulls in its capabilities; the
   images' role choice becomes role plus the admin-space capability.
5. **The C ABI on MCU** (C12). Register the atom, split the definition layer out,
   generate the headers, implement the MCU driver. Done when the pico example
   programs in the `maps` range give the same results on the MCU images and the
   static variant links no allocator.
6. **Stream links on MCU.** Build lwIP's TCP and bind Zephyr's stream sockets;
   generalise the peer address out of the datagram signatures; move the stream
   framing out of the tokio crate into a `no_std` state machine both runtimes use;
   hold a transmit slot until the write completes; one host serves both link kinds
   through a closed driver enum.
7. **Storage policy completed** (C3, C4, C5). Capacity as the table's const
   parameter, the image's policy named, `bounded-heapless` and `session-slot`
   removed, the matching watches, observer staging and scratch buffers on the
   policy, and the advanced publisher and subscriber's state machine moved into
   session-core so the static variant exists (after the liveliness plane's
   allocation-free sink).
8. **The `exec` axis.** pico runs a read task and a lease task under
   `Z_FEATURE_MULTI_THREAD` and takes their attributes (`z_task_attr_t`); wz on MCU
   runs one cooperative task. First rewrite, as one table, which task touches each
   cell that is `Sync` today on the single-task rule; then a task seam in which the
   runtime supplies task bodies and attributes and the image creates the tasks. The
   multi-task value is not selectable until the table is complete. This axis is wz's
   own tasks on an MCU; which of pico's two C header arms the host drop-in serves is a
   separate choice, already selectable as the `multi-thread` capability.
9. **Policies that change the shape of the code**, each by section 5 and C3 (a
   strategy type parameter).
10. **Platforms and packaging**: FreeRTOS+TCP, QNX, an installable SDK.
11. **`wz-config`** (section 6, C9).
12. **Rust API compatibility** (C13). Register `api-compat-rust`; derive the
    upstream surface from rustdoc JSON; the compatibility crate; the surface gate;
    upstream's examples and public API tests built against it.
13. **Resource gates** (D5): stack peak and wire turnaround per registered profile,
    each a committed figure that a change moves visibly.
14. **SCE as a configuration axis**: the state machine's feature gates
    (`feature_inventory.md` §8) driven by the same declaration, checked by `--check`.

Order: 1 first. 2, 3, 4, 6, 7, 8, 11, 12, 13 and 14 depend on 1; 5 on 1 and 2; 9 on 4
and 7; 10 on 5.

## 8. Open

- Whether the storage trait aligns its names with the codecs' `CodecStorage`
  (SCE, read-only from here).
- The header generator of C12.
- What SCE needs to accept a feature selection from the declaration (step 14), to
  be asked of the SCE repository.
