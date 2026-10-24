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

- **One declaration** (`deploy/wz-config.toml`, step 1 begun): the capabilities and the
  limits, with a `catalog_version`; `scripts/lib/wz_config.py` generates
  `deploy/Kconfig.capabilities`, `deploy/Kconfig.limits` and the value module of the limits,
  turns a `.config` or a pico `config.h` into cargo arguments, and `--check`s the generated
  files, the limit bindings of `caps.rs` and the three capi manifests against it.
- **Capabilities of the C ABI builds**: thirty-one, on by default except those the reference
  library also leaves off (`admin-space`, `local-subscriber`, `local-queryable`,
  `multicast-declarations`, `raweth-transport`). Four change the layout of structs a pico
  program allocates, so a program links the build of the header arm it compiled against:
  `multi-thread` (off is pico's single-threaded C ABI), `unstable-api` (off is the option
  layout of upstream's default header) and the two local switches (on adds a locality
  field to seven option structs). No Kconfig `rsource`s the generated file yet; the MCU
  images do not see it.
- **Limits**: twenty-three, each read in the generated module as
  `limit(option_env!("WZ_LIMIT_<NAME>"), default)` and bound to the name the code uses in
  `crates/wz-session-core/src/caps.rs`; the Zephyr build turns each `CONFIG_WZ_LIMIT_*`
  into the cargo environment (`deploy/zephyr-common/wz_zephyr_board.cmake`). `limit()`
  reads a decimal `usize` only.
- **Drop-in and extension (C10)**: `scripts/lib/drop_in_header_gate.py` holds the pico
  drop-in header (`wz_capi_pico.h`) to the functions zenoh-pico's own header declares at the
  pin, read through the preprocessor under its defaults, every switch on and every switch
  on single-threaded (its `config.h` rendered from the pinned template, no build tree), and
  `wz_ext.h` (`crates/wz-capi-core/include/`) to `wz_ext_*`; both are empty of doors yet, as
  is the Rust `wz::ext`. zenoh-c has no drop-in header of wz's (programs include upstream's
  `zenoh.h`); its wz-own doors are `wz_capi_c_*` in `wz_capi_c.h`, the prefix they were
  published with, and move to `wz_ext_*` only with the consumer told first.
- **The MCU images' axes**: the admin node's network stack, role and memory profile are
  declared in `deploy/wz-config.toml` (`[[image]]`, `[[axis]]`, `[[axis_option]]`,
  `[[cargo_rule]]`). The generator writes the image's `Kconfig.axes` (each axis a
  `choice`, each option's `requires` its `depends on`) and `wz_axes.cmake` (the image
  crate's features and whether its defaults are off), and the image's Kconfig and
  CMake read them. Every image of the board table and every stack its overlays
  document builds with the same cargo line as before the move
  (`scripts/lib/zephyr_cargo_lines.py`). What a board or a driver adds (the MAC, the
  pools, 10BASE-T1S, the SPI probe) and the client's parameters stay in the image's
  own Kconfig and CMake. The crate's features are per combination (the client on the
  heap is `client-node`, on statics `fixed-client`), and they stay so: cargo cannot
  express "this option and that one" with one feature per option (C3), so a
  conjunction is a `[[cargo_rule]]` whose `when` names both options.
- **Global axes**: an `[[axis]]` with no `image` belongs to no one image. The
  generator writes it to `deploy/Kconfig.axes`, which the root `deploy/Kconfig`
  sources first. Its options may `implies` capabilities, which become `select`s, and
  an image's cargo rule may name them. An image's Kconfig that sources
  `../Kconfig.axes` must also source `../Kconfig.capabilities`, and `--check` holds
  that. The declaration has no global axis yet: `family` and `target` come with step 2,
  `role` with step 4.
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
  17 cargo features. The pico and zenoh-c rows are the declaration's `[[upstream_switch]]`
  (step 2), and a zenoh-pico `maps` row to a capability is its pico switch, written once.
  The relation is not one to one: either of pico's advanced switches asks for the one
  wz advanced plane, the multicast transport needs both of its switches
  (`pico_combine = "all"`), and pico's liveliness get needs two switches of other
  capabilities (`pico_flags_all`). A pico header that states off a capability wz would
  have to add for one it turns on (the advanced subscription with the unstable API
  off, since wz's advanced plane implies it) is refused by `--features` rather than
  built with other struct layouts.
- **The zenoh-c drop-in's ABI arm from an installed zenoh-c** (step 2): zenoh-c's
  `zenoh_configure.h` defines one `Z_FEATURE_*` per cargo feature it was built with (its
  own table, `buildrs/cbindgen_generator.rs`), and two of them move the C types a program
  allocates, the unstable API and shared memory. Their rows name the macro (and the
  unstable one its inverse sense), and `wz_config.py --drop-in-features c <header>` is the
  one rule that turns a header into the wz-capi-c build: the arm's features ADDED to the
  default, which sits at the origin of both axes (open-debt item 616). Layer C1cc's
  selector calls it, `zenoh_c_archive_arm.py` grades it on all four arms, and the switch
  map holds the macros to zenoh-c's table. The two layout switches are axes, not
  capabilities (C3: what changes the shape of the code is never a feature that adds it):
  flipping the inverse one into an additive capability would put the no-unstable arm
  behind `--no-default-features`, which a dependent enabling the default undoes. Their
  end state is C12's, the layout a value of the generated ABI, not a cargo feature.
- **Each original's own defaults** (step 2): every capability states, for the originals
  its ABIs reach, whether that original's default build has it (`upstream_on` /
  `upstream_off`); the switch map holds zenoh-pico's to its CMakeLists and zenoh-c's to
  its default features. The capability's `default` stays the drop-in's own.
- **The Rust API compatibility family** (step 12): `api-compat-rust` replaces zenoh's Rust
  crates by a family of crates under UPSTREAM'S package names, versioned as the pin, that a
  user swaps in with one `[patch.crates-io]` entry per crate. The name is the mechanism:
  Cargo swaps by package name, and a patch whose package is named otherwise is not used (measured: the
  graph kept upstream's crate, and an ecosystem crate then met a second, different type). A
  program that depends on `zenoh` and on an ecosystem crate (`zenoh-ext`, a plugin) must meet
  one `zenoh_core` and one `zenoh_result`, so the family is every crate the public API names
  and the ecosystem imports, not `zenoh` alone, and a one-line `package = "wz-zenoh"` rename,
  which cannot reach the crates under it, is not offered. `rust_api_surface.py` lists the family
  (`MEMBERS`), emits each member's rustdoc surface with the same normaliser as upstream's and
  holds it to every upstream arm: no line upstream lacks (C10), and the missing count as a
  ratchet that a slice lowers in its own round. A function's line carries its signature
  (generics and bounds, parameter and return types, qualifiers, the `impl` block of a method),
  so a path with the wrong signature is a missing line and not a present one. Members so far:
  `zenoh-result` (complete: 37 of 37 lines), `zenoh-runtime` (complete: the process-wide pool, so
  the one crate of the family that holds global state, and the reason it is a member and not a
  detail of `zenoh-core`) and `zenoh` (`crates/wz-zenoh`, empty: 709 of 709
  default lines missing, named `wz-zenoh` until the slice that makes it patchable renames it).
  Behaviour is held beside the surface by Layer E18 (`conformance/`): a differential test of each
  crate against upstream's, a graph in which an upstream crate and the wz crate meet one type once
  patched, and the same graph unpatched as its control. The packages are not published (the
  names are upstream's); a deployer reaches them by path or git in the `[patch]` table.
- **One pinned Kconfig interpreter on the host** (step 1, C11): `kconfiglib` 14.1.0, the
  version Zephyr bundles, pinned by hash (`scripts/requirements-kconfig.txt`) and provisioned
  into `target/kconfig-venv` by `scripts/provision-kconfiglib.sh`. `wz_config.py
  --resolve-features` / `--resolve-env` merge presets onto the defconfig of the original
  their `# base:` names (section 6), strictly (C9, with Zephyr's merge settings and its two
  value checks as errors), and Layer C0 resolves every registered profile and every upstream
  defconfig. `wz_config.py --check-equivalence` resolves the defaults, the upstream defconfigs
  and every registered profile with both the pinned copy and the one Zephyr's build runs and
  compares every symbol's value; Layer Qz runs it where the Zephyr tree is, armed. The
  upstream defconfigs join its inputs when step 2 writes them.

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
user means changing the dependency graph and nothing in the program; wire, behaviour and
API must all match. The replacement is a family of compatibility crates that carry
upstream's package names and the pinned version, so that one `[patch.crates-io]` entry per
crate swaps them in and every crate of the graph, an ecosystem crate included, meets the same
types. It exposes the pinned crates' public APIs over wz, each held by a surface gate derived
from the upstream crate's rustdoc JSON and by differential tests against it. (Refined
2026-10-24 from "changing one dependency line": the swap is by package name, which a
`package = ` rename on the dependency line does not reach, so the unit of replacement is a
`[patch]` block and not a line.)

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
its `CMakeLists.txt` sets. The three host ones are generated (`wz_config.py --emit
defconfig:<original>`, held by `--check`): the original's choice on each global axis
(the global axes' options name the originals whose choice they are, `upstream_on`; the
role is the only one so far) and every capability it is judged for whose value differs
from the Kconfig default (`upstream_on` / `upstream_off` on the capabilities). Layer
C0's `--check-presets` resolves each one strictly and holds it to its original's
values. The original is not a Kconfig symbol: nothing a build compiles reads it, and a
preset names it in its `# base:` line, which is what selects the defconfig it merges
onto. `target` and the MCU defconfig wait for the images' trees to resolve the host
declaration's symbols (the admin node sources the global axes since round 3445; its
own symbols are not in the host tree). wz's pico interop lanes compare against a reference build
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

1. **One declaration and its generator** (C1, C2, C3, C6, C10, C11). Move the
   capabilities, the limits and the axis-like symbols of the MCU images into
   `deploy/wz-config.toml`; one generator (`wz_config.py`) replaces the capability and the
   limit generators (done for the capabilities and the limits); the images use the
   generated Kconfig and CMake bridge; place
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
    upstream surface from rustdoc JSON; the family of compatibility crates, lowest first
    (`zenoh-result`, `zenoh-runtime`, `zenoh-core`, `zenoh-macros`, `zenoh-keyexpr`,
    `zenoh-protocol`, `zenoh-config`, `zenoh-util`, then `zenoh`); the surface gate over each; differential tests against
    each; upstream's examples, tests and an ecosystem crate built against the patched graph.
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
