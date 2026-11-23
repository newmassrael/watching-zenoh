# wz-fuzz

Coverage-guided fuzz targets, built with libFuzzer and AddressSanitizer by the
nightly `rust-toolchain.toml` here pins. `scripts/fuzz.sh` builds, seeds,
replays and runs them; Layer Fz of `scripts/run-ci.sh` replays every seed and
committed reproducer through each target on every push, and
`.github/workflows/fuzz.yml` fuzzes each target every night.

## What is fuzzed

Two surfaces take bytes wz did not make.

**The C ABI doors a consumer hands outside bytes to** (package `wz-fuzz`):

| target | what it drives |
|--------|----------------|
| `pcap` | the capture doors of `wz-capi-dissect` |
| `live` | the live-dissection doors, fed a capture packet by packet |
| `transport` | the doors that read one transport message |
| `text` | the filter, keyexpr and declaration-text doors |
| `proto` | the schema doors |
| `e2e` | the end-to-end protection profile doors |
| `selector_term` | the field document's sentences, held to the soundness oracle |
| `replay` | the mutation and plan doors of `wz-capi-replay` |
| `config` | the config verdict of `wz-capi-c` |
| `sender` | the end-to-end sender of `wz-capi-c` |

**The network ingress, the bytes a peer sends into a session.** Each target
reads its input as the units of a link, each behind its two-byte
little-endian length, as a stream link frames them:

| target | package | what it drives |
|--------|---------|----------------|
| `ingress_frames` | `wz-fuzz` | `wz-session-core` with no session: each unit walked message by message (`parse_inbound_consuming`, its observer form and its form over a unit that can be shared), each Frame's records walked strict, best-effort, as a rejoined chain and as a lowlatency unit, and read again with each network message's lent codec, and each Fragment handed to a reassembly Router, lending or borrowing its completed chains |
| `codec_roundtrip` | `wz-fuzz` | the generated codecs of the network messages (Push, Request, Response, ResponseFinal, Declare, Interest, Oam), each value read from a peer's bytes held to its round trip |
| `session_unicast` | `wz-fuzz-session-heap` | a unicast session of the heap profile, driven by the cooperative runtime's pump through the copying receive and the reassembly, into an application layer with a subscriber and a queryable on every key |
| `slot_session` | `wz-fuzz-session-slot` | a session of the per-session slot profile (the MCU client node's), read in place, with the session shell's slot application layer on its events |
| `coop_read` | `wz-fuzz-coop-engine` | the cooperative engine behind the C ABI (`wz-capi-coop`), read as a C program reads it, with a subscriber and a queryable on every key |

The three session targets open their session to a far end the harness plays:
it answers the session's dial with the hand-written InitAck and OpenAck of
`wz-session-wire-fixtures`, and every unit of the input reaches the session
after that, as a datagram from that peer. No socket is opened: the link is the
harness's. A target fails on every input when that handshake does not open the
session, so a harness that no longer opens one is seen at once and not as a
night of fuzzing that reached nothing.

What each target holds beside not crashing, reading out of bounds or leaking
is stated in its header comment. In short: the reads of one message agree
across their forms and account for every byte; the owned and lent walks of a
Frame read each record at the same bytes; a codec's value survives its round
trip; the Router delivers a chain exactly when it says it completed one; every
outcome a session reports renders; a heap session's live heap grows by less
than `GROWTH_LIMIT` (`ingress-common`) on any input; a slot session
allocates nothing from its handshake to its last datagram and gives its slot
and its pump cell back.

## Why several packages

Cargo unifies the features of the packages one invocation builds. The session
targets build the session shell on three profiles (the heap profile, the
per-session slot profile, the C ABI's engine), which must meet neither each
other nor the dissector's selection, so each is a package of its own and
`fuzz.sh build` builds each package in an invocation of its own
(`scripts/lib/fuzz_seeds.py --packages` names the package of each target).
`ingress-common` is what the ingress targets share, and depends on no crate
of the session shell for the same reason.

## Seeds

`scripts/lib/fuzz_seeds.py` writes each target's seeds from the files this
tree holds. An ingress target's seeds are the UDP and TCP payloads of the
captures under `captures/`, as the units of one stream per capture, and a
few units written there (an empty Frame each way, a KeepAlive) for a tree that
holds no capture of a session.

## Running one

```
bash scripts/fuzz.sh regress ingress_frames      # every seed and reproducer once
bash scripts/fuzz.sh run slot_session 600 2      # fuzz for ten minutes, two workers
```

A crash is written to `crates/target/fuzz/artifacts/<target>/`; the commit
that fixes it copies the input to `regressions/<target>/` (`regressions/README.md`).
