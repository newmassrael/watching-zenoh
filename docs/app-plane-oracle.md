# The application-plane oracle lane

`scripts/app-plane-oracle.sh` holds wz's application plane against a deployed peer's own
build: wz's end-to-end protected frames, the counter rules its receiver judges by, its replay
answers and the segmented pieces they travel as are exchanged with a program built from the
deployment's own layer, over a session on the loopback, in both directions, and compared byte
for byte and verdict for verdict. The deployment's documents are not read; its build is the
oracle.

The repository holds the lane and wz's side only: the lane script, wz's party
(`scripts/app-plane-oracle/wz_party.c`) and the judge (`scripts/app-plane-oracle/oracle.py`).
The deployment's party, its profile documents and every value of its deployment stay outside
the repository and are named by the environment.

## Running it

```sh
WZ_APP_PLANE_ORACLE_DIR=<the deployment's party project> \
WZ_APP_PLANE_ORACLE_PROFILE=<the lane file> \
    bash scripts/app-plane-oracle.sh
```

| Variable | What it names |
|---|---|
| `WZ_APP_PLANE_ORACLE_DIR` | the CMake source directory of the deployment's party (below) |
| `WZ_APP_PLANE_ORACLE_PROFILE` | the lane file: the checks and wz's documents for them (below) |
| `WZ_APP_PLANE_ORACLE_CMAKE_ARGS` | optional words added to the party project's configure, such as where the deployment's checkouts are |
| `WZ_APP_PLANE_ORACLE_SCRATCH` | optional; where builds and transcripts go, by default `target/app-plane-oracle` under the artifact root |

`bash scripts/app-plane-oracle.sh --selftest` runs the judge on synthetic transcripts and
nothing else; the lane runs the same selftest before anything it measures.

| Exit | Meaning |
|---|---|
| 0 | PASS: every aspect of every check agreed |
| 1 | FAIL: an aspect disagreed, a party did not finish, or the judge failed its selftest |
| 2 | a variable or the lane file was refused (the judge says which field and why) |
| 3 | NOT-MEASURED: the two variables are not both set, or one side did not build, so nothing was exchanged |

A NOT-MEASURED run has shown nothing, and the lane never passes in its place.

It is a local lane, opt-in by its variables: it needs a deployment's build, which no hosted
runner has. It is not a layer of `scripts/run-ci.sh`, whose every layer the hosted workflow
runs. It runs on Linux.

## What a run does

1. The judge's selftest.
2. `oracle.py prepare` reads the lane file and writes one check directory per check.
3. wz's party is built by `scripts/pico-c-program.sh` against the pico C ABI with the
   `e2e-sender`, `e2e-receiver`, `segment-sender` and `replay-cache` capabilities (and the
   lane file's own additions), once for each reply shape the checks need: the
   `replay-reply-shape` policy is a build default, so a check with a segment profile gets a
   build with `segmented`. Each build's library is copied beside its party, and the party runs
   against that copy.
4. The deployment's party project is configured out of tree into the scratch directory and
   built (below).
5. Each check runs twice: wz sends and the deployment receives (`wz-sends`), then the other way
   round (`peer-sends`). Each run gets its own copy of the check directory.
6. `oracle.py judge` reads the four transcripts of each check and prints one line per aspect.

## The lane file

A JSON object. The values below are SYNTHETIC; a deployment states its own.

```json
{
  "wz": {"features": "shared-key-ids", "build_env": {}},
  "session": {"connect_mode": "client"},
  "key_ids": {"dictionary": [{"id": 7, "key": "lane/e2e/small"},
                             {"id": 9, "key": "lane/e2e/large"}],
              "forms": {"listen": "shared", "connect": "shared"}},
  "checks": [
    {"name": "small-frames", "kind": "e2e", "key": "lane/e2e/small",
     "profile": "profiles/small.json", "values": {"ident": 4660},
     "payload_len": 12, "skip_beyond_gap": 3, "first_counter": 0,
     "peer": {"message": "small"}},
    {"name": "large-frames", "kind": "e2e", "key": "lane/e2e/large",
     "profile": "profiles/large.json", "values": {"ident": 4661},
     "payload_len": 900, "skip_beyond_gap": 3,
     "segment": {"profile": "profiles/pieces.json", "values": {"origin": 9},
                 "first_transfer": 0, "chunk_bytes": 256},
     "peer": {"message": "large"}},
    {"name": "answers", "kind": "replay", "key": "lane/replay/one", "suffix": "/ask",
     "profile": "profiles/large.json", "values": {"ident": 4661},
     "payload_len": 600, "frames": 4, "depth": 4,
     "segment": {"profile": "profiles/pieces.json", "values": {"origin": 9},
                 "first_transfer": 0, "chunk_bytes": 256},
     "peer": {"message": "large"}}
  ]
}
```

| Field | Meaning |
|---|---|
| `wz.features` | wz-capi-pico features wz's party needs beyond the four above, a comma list |
| `wz.build_env` | `WZ_POLICY_*` and `WZ_LIMIT_*` values wz's build states, as a deployment's node would be built; `WZ_POLICY_REPLAY_REPLY_SHAPE` is refused, the lane states it per check |
| `session.connect_mode` | the mode of the side that dials: `client` (default) or `peer` |
| `key_ids.dictionary` | optional: the key ids every node of the deployment shares, `[{id, key}]`; each id 1 to 65535 and named once, each key a canonical key expression named once. wz's party hands it to `wz_ext_config_key_ids` before it opens, in every role, so its session reads a key named by one of these ids though nobody declared it. It needs `shared-key-ids` in `wz.features`, and is refused without it |
| `key_ids.forms` | optional: the key-wire form (`declared`, `shared` or `literal`) of the `listen` side's endpoint and of the `connect` side's, which wz's party states with `wz_ext_config_key_wire_form_for`; a side not named takes the session's form, the `key-wire-form` policy, which `wz.build_env` may state |
| `name` | lower-case letters, digits and dashes; the check directory's name |
| `kind` | `e2e` (protected frames on a key) or `replay` (a replay cache and the subscriber that asks it) |
| `key` | the key expression the frames travel on |
| `profile`, `values` | wz's end-to-end profile document and its header values, as `wz_ext_e2e_sender_new` and `wz_ext_e2e_receiver_new` take them: an inline object, or a path relative to the lane file |
| `payload_len` | the length of every synthetic payload, at least 1 |
| `skip_beyond_gap` | `e2e`: how many frames the sender holds back in one run so that the next frame's counter step is beyond the deployment's allowance (for an allowance of N steps, N) |
| `first_counter` | the counter of a stream's first frame, 0 by default |
| `suffix`, `frames`, `depth` | `replay`: the suffix the cache serves on, how many frames it records, its ring depth (at least `frames`) |
| `segment` | optional: the segment profile and values documents, the first transfer number and the chunk size; its presence makes the check `segmented`. Under `replay` the answers travel as these pieces. Under `e2e` every frame put travels as them, for a message a deployment always sends cut: both senders cut each put, the next transfer number each, and both receivers join before they judge |
| `suffix` under `e2e` | optional with a `segment`: wz's receiver joins pieces in its replay subscriber, which watches for a cache on the key and this suffix and is answered by none; `/lane-no-cache` by default. A lane file whose `wz.build_env` states `replay-live-before-answer` `hold-back` is refused for such a check, since no round ever releases what it holds |
| `peer` | any JSON, written to the check directory as `peer.json` for the deployment's party; wz's party does not read it |

## The party contract

Each side is a program with the same arguments and the same transcript:

```
<party> <role> <check-dir> listen <locator>
<party> <role> <check-dir> connect <locator> <client|peer>
```

Roles: `send` and `receive` for an `e2e` check, `serve` and `ask` for a `replay` check. The
receiver and the cache listen; the sender and the asker dial. The locator is a TCP locator on
the loopback.

The check directory holds:

| File | Content |
|---|---|
| `params` | one `name value` per line: `kind`, `key`, `expect` (how many frames the receiving side is handed), `first_counter`, `frame_max`, `segmented` (0 or 1), with a segment `first_transfer` and `chunk_bytes`, for `replay` (and a segmented `e2e`) `suffix` and `depth`, and with `key_ids.forms` `key_form_listen` and `key_form_connect` |
| `key-ids` | with `key_ids`: one `<id> <key>` per line, the dictionary the session opens with |
| `plan` | one `<action> <payload hex>` per frame, in the order the frames are built |
| `profile.json`, `values.json` | wz's documents for the check |
| `segment-profile.json`, `segment-values.json` | the same for the pieces, under `segmented` |
| `peer.json` | the lane file's `peer` object |
| `go`, `stop` | created by the lane while the parties run |

The actions of an `e2e` plan: `send` puts the frame once; `twice` puts it twice; `hold` builds
it, which spends its counter value, and puts nothing; `corrupt` puts a copy whose last byte is
XORed with 0x01, then the frame. Every frame of the plan is built, whatever its action. The
`replay` plan's action is `record`: the cache records every frame before it serves.

What each role does:

- every role opens its session with the dictionary in `key-ids`, when there is one, and the
  form `params` states for its own side (`key_form_listen` or `key_form_connect`) on its
  endpoint.
- `send`: build every frame, print each; dial; put a probe on `<key>/probe` every 50 ms until
  the file `go` exists; carry out the plan; keep the session until `stop` exists. Under
  `segmented` each put is the pieces of the frame, printed as they go out.
- `receive`: subscribe to `<key>` and `<key>/probe`, print `ready`; print `probe` once a probe
  arrives; judge every frame of `<key>` as it arrives until `expect` frames came. Under
  `segmented` a frame is judged once its pieces are joined.
- `serve`: build and record every frame, print each (and, under `segmented`, the pieces each
  is cut into, numbered from `first_transfer` as a first answer numbers them); serve on
  `<key><suffix>`; print `ready`; keep serving until `stop` exists.
- `ask`: ask the cache that appears on `<key><suffix>`, judge every answer, and finish when
  the round is over.

Transcript lines, on standard output:

| Line | Who |
|---|---|
| `ready` | every role, once its entities are declared |
| `probe` | `receive`, once |
| `frame <i> <hex>` | `send`, `serve`: frame `i` of the plan as built |
| `piece <i> <j> <hex>` | under `segmented`, piece `j` of: frame `i` of the plan (`serve`), or the `i`-th put, counted from 0 in the order put (`send`) |
| `got <n> <class> <payload hex>` | `receive`, `ask`: the `n`-th frame handed to it, its class and its payload |
| `round <live\|abandoned>` | `ask`: how the round ended |
| `refused <text>` | any role refused before it exchanged anything |
| `done` | the role ran to its end |

The exit status is 0 when the role ran to its end, 1 when it gave up waiting, 2 when it was
refused. Other lines are allowed and ignored.

A class is what every implementation's receiver can say of a frame:

| Class | wz's verdict | Meaning |
|---|---|---|
| `intact` | `WZ_EXT_E2E_OK`, `WZ_EXT_E2E_FIRST` | the checks hold and the counter is acceptable |
| `counter` | `WZ_EXT_E2E_REPEATED`, `WZ_EXT_E2E_OUT_OF_RANGE`, `WZ_EXT_E2E_COUNTER_ERROR` | intact, but the counter breaks the rules |
| `integrity` | `WZ_EXT_E2E_INTEGRITY` | the CRC, the identifier or the length failed |
| `other` | anything else | no verdict of these |

## What the judge holds

For every check:

- **ran**: all four parties left status 0, said `done`, and refused nothing.
- **frames byte for byte**: both senders printed every frame of the plan, and frame `i` of
  wz is frame `i` of the deployment's, byte for byte.

For an `e2e` check:

- **arrivals**: each receiver was handed every frame put.
- **verdicts owed**: the first three arrivals are `intact`, the repeat is `counter`, the first
  frame after the held run is `counter`, the corrupted copy is `integrity`.
- **same verdicts both ways**: arrival `n` has the same class whichever side judged it. This
  is where the rules a deployment chooses (a single lost frame, what follows a counter error,
  what follows a corrupted frame) are held without the repository stating them.
- **payloads**: every arrival that is not the corrupted copy carries the payload sent.

For a `replay` check:

- **answers in order**: each asker was answered every recorded frame, in the order recorded,
  each `intact`, and its round ended `live`.
- **pieces byte for byte** (under `segmented`): both caches printed the pieces of every
  frame, and they are the same bytes.

For a segmented `e2e` check, also **pieces byte for byte**: both senders printed the pieces of
every put, a repeat and a corrupted copy each under a transfer number of its own, and they are
the same bytes.

## Pointing it at a deployment's build

The deployment writes, outside this repository, a CMake project whose build directory holds a
program named `app-plane-oracle-peer` that speaks the contract above over the deployment's own
layer: its protection, its counter rules, its replay cache and its pieces, as its nodes build
them. The lane configures the project with two cache variables:

| Variable | Value |
|---|---|
| `WZ_ORACLE_PICO_INCLUDE` | the pico headers of the wz library's arm and wz's extension header directory, a CMake list |
| `WZ_ORACLE_PICO_LIBRARY` | the wz pico library built for the lane |

so a deployment whose glue is written against zenoh-pico's API can link its own layer to wz's
pico C ABI in place of zenoh-pico, and the oracle is that layer over wz talking to wz's
application plane. A deployment whose layer sits on its own session layer builds that instead
and leaves the two variables unread. Either way the program's frames, verdicts and answers are
the deployment's own code's.

The lane file then states, for each check, wz's profile and values documents describing the
same message the deployment's party sends, and `peer` carries whatever that party needs to pick
its message. Where a header field is derived from a node's address, both sides must derive it
from the same value: state it in wz's values text and in `peer`.

What it does not show: a deployment's session-layer behaviour beyond what a session between
the two parties exercises, timeouts (both sides run on one clock and no frame is late), and
anything of a deployment's layer that cannot be built on a Linux host.
