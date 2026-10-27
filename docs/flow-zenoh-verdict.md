# Whether a flow is zenoh: a sequential test over state invariants

Status: design note. It states what is built, what is decided and what is
still open. It is not a specification and the atomic store does not parse it.
It answers a consumer claim filed on 2026-10-26: move the per-flow zenoh
verdict from a fixed rule to a sequential probability ratio test whose
thresholds wz owns, so that a consumer draws the verdict and its basis
instead of holding thresholds of its own.

## 1. The question

A passive reader is handed a flow and must say whether its bytes are zenoh.
Until this note the answer was a rule (field document revision 41 to 42,
session table revision 3 to 4): `proven` when at least one Init, Join, Scout or
Hello of version 0x09 decoded from a framing unit read whole, and no message of
another version did. Two defects follow from that rule, both measured:

- **One header is a verdict.** A DNS id of `0x6109` or `0x4709` writes a Scout
  or a Join header followed by the version byte, and the flow is `proven`
  (`a_dns_datagram_whose_id_reads_as_a_join_header_is_proven`, 2 in 4200
  generated DNS flows).
- **Everything else is `unproven`.** A zenoh session the capture joined after
  its handshake carries no Init, so it gets the word arbitrary bytes get, and
  the consumer was left to separate the two with its own thresholds on
  `unit_readings` (ten units, a share of 0.75). Generated structured protocols
  reach a share of 0.6 at ten units
  (`structured_datagrams_of_other_protocols_read_by_their_first_byte`).

## 2. The test

Two hypotheses about one flow. H1: the bytes are zenoh transport as this
reader reads it (protocol version 0x09). H0: they are not. A zenoh flow of
another version is a separate question, answered by its own cell (section 4).

Each observation `o` adds `log2(P(o | H1, past) / P(o | H0, past))` to the
flow's log likelihood ratio `L`. The verdict is read off `L` against two
thresholds fixed by the error rates:

| verdict | condition |
|---|---|
| `yes` | `L >= log2(1/alpha)` |
| `no` | `L <= log2(beta)` |
| `undecided` | otherwise |

`alpha = beta = 2^-20`, so the thresholds are +20 and -20 bits.

**The verdict is reported at every moment, not frozen at the first
crossing.** That is sound because, when every increment is a true conditional
likelihood ratio, `2^L` is a nonnegative martingale under H0, and Ville's
inequality bounds the chance that it EVER reaches `1/alpha` by `alpha`
(and symmetrically for H1 and `beta`). The bound covers a live tap that reads
the verdict after every packet. Wald's `(1 - beta) / alpha` is not used: it
assumes one decision at a stopping time.

**Several null protocols, two statistics (model 2).** H0 is a family (DNS,
mDNS, SSDP, RTPS, ...). For an outcome whose H0 probability differs across the
family, the `yes` statistic uses the LARGEST probability any member shows. It
is then at most the true ratio against every member, so the false `yes` is
bounded against each member of the corpus at once. Those largest
probabilities sum to more than one over an observation's outcomes, so the
same statistic read for `no` bounds nothing: under H1, `2^-L` is a martingale
only when the denominator is a proper distribution. The `no` statistic uses
one, the average of the members' (any proper distribution bounds the false
`no`). Each observation therefore weighs twice, `yes` is read on the first sum
and `no` on the second, and a flow whose two sums both cross is `undecided`.
Model 1 kept one sum and claimed both bounds; only the false `yes` held. An
observation must also be weighed on every outcome it can have: one weighed
only when it confirms (model 1's `version_header`) raises the `yes`
statistic's expectation under H0. Neither bound holds against a protocol the
corpus does not contain; that is the limit the claim states and the reason
for section 6.

**The port is not evidence.** The thresholds are a statement about the bytes
under H0, and a prior odds from the port would move that statement by an
amount nobody has measured. A posterior beside the verdict needs base rates
per port, which only a corpus of real captures gives (section 6).

## 3. The observations (model 1)

This section is model 1, kept as it was written; model 2 (section 6.2)
measures the unit weights, adds `stream_framing`, weighs another version
against the flow and keeps two sums.

Each check has a strength, a probability under H0 (`q`, the chance a
non-zenoh flow satisfies it) and a probability under H1 (`eps`, the chance a
zenoh flow fails it: loss, reordering, a capture that began mid-session).
Each side of each check names its basis: `derived` from field widths,
`generated` from the generated corpus in
`crates/wz-capture/src/session_table_tests.rs`, or `assumed` and waiting for a
measurement. Weights are written in millibits.

| check | strength | observed when | confirm | violate | q basis | eps basis |
|---|---|---|---|---|---|---|
| `cookie_echo` | `handshake` | an OpenSyn follows an InitAck of the other direction, both read whole | `8000 * min(len, 8) - 1` | `-10000` | derived: `2^-(8 len)`, capped at the 64-bit hash | assumed: `2^-10` |
| `init_roles` | `handshake` | both directions sent an Init read whole | `999` | `-9000` | derived: `1/2`, two Inits of opposite kind by chance | assumed: `2^-10` |
| `sn_follows` | `state` | a Frame or Fragment after an earlier one on its conduit | `7907` | `-3994` | derived: a varint equals a given value with chance at most `2^-8` | assumed: `2^-4` |
| `version_header` | `header` | an admissible Init, Join, Scout or Hello of version 0x09 read whole | `8000` | none | derived: the version byte, `2^-8` | none: another version is the version cell's question |
| `unit_reading` | `unit` | every framing unit | `2603` (explained) | `-6745` (residual), `-7000` (undecoded) | generated: the largest share over the corpus (mDNS 0.162 explained, mDNS 0.838 residual, SSDP 1.0 undecoded) | assumed: `2^-7` each for residual and undecoded |

Notes on the table:

- `sn_follows` is judged WITHOUT the ring when no InitAck or Join gave one: the
  step "the next integer" needs no mask, which is the rule the reassembly
  dispatcher already applies to a chain it follows without a ring. This is
  what lets a session the capture joined after its handshake reach `yes`.
- `q` for `sn_follows` is exact only against bytes that do not count. A
  protocol with a counter where a zenoh SN would sit (a CoAP message id, an
  RTPS sequence number) can beat it. That is a measurement for section 6, not
  a bound this note can claim.
- The kind of a unit's front message is assumed to carry no evidence beyond
  the checks above. It is neither a conservative nor an anti-conservative
  assumption, and the corpus replaces it.
- Each of the eight model constants is written as a literal and recomputed
  from its stated probabilities by a test, so a literal cannot drift from its
  derivation.

What this gives, worked out from the table:

- The DNS datagram whose id reads as a Join: `2603 + 8000` = 10.6 bits,
  `undecided`. A DNS flow of ten datagrams: about eight undecoded units, `no`
  after three.
- A zenoh session joined mid-stream: each Frame unit adds `2603 + 7907` once
  its conduit has a baseline, `yes` after two or three units.
- A full handshake: the cookie alone is 64 bits, `yes` on the OpenSyn.

## 4. The documents

The `zenoh` key keeps its name and takes the words `yes`, `no`, `undecided`.
Two keys arrive beside it on every flow object of the field document and on
every row and flow of the session table:

- `announced_version`: `none`, `own`, `foreign`, `mixed`. What the
  version-bearing messages said, the old rule's evidence kept as a separate
  answer.
- `zenoh_evidence`: `{"log2_lr_millibits": L, "yes_at_millibits": 20000,
  "no_at_millibits": -20000, "model": 1, "checks": [...]}`, one entry per check
  that observed anything: `check`, `strength`, `confirmed`, `violated`,
  `millibits`, `q_basis`, `eps_basis`.

The field document moves to revision 43 and the session table to revision 5.
The value change is the notice a revision row carries
(`crates/wz-capture/src/doc_revision.rs` @ `R2175 (open-debt item 552) — THE VALUE FAMILIES`).
The selector's `zenoh` term takes the new words.

## 5. Not in model 1, and why

- **A declared id referenced later, a request answered, a KeepAlive inside the
  lease.** The reader decides the first two only from held messages
  (`crates/wz-capture/src/interest.rs`, `crates/wz-capture/src/exchange.rs`),
  so they do not survive a retention ceiling, and nothing compares KeepAlive
  spacing with the lease. Each needs an ingest-time tally first. Their `eps`
  also depends on where the capture began (a declaration made before the
  capture reads as unresolved), which needs real H1 captures to price.
- **Fragment reassembly** beyond the SN steps already counted: its independent
  part is whether the joined batch parses, whose `q` needs a corpus.

## 6. Steps after model 1

1. **Corpus.** H1: real zenoh captures, mid-session, lz4, several versions. H0
   from real devices: mDNS, DNS, SSDP, RTPS, SOME/IP first, then LLMNR,
   WS-Discovery, NTP, DHCP, CoAP, MQTT, QUIC, and structured TCP (HTTP, MQTT,
   TLS). Real captures are committed under `captures/` after anonymisation
   (addresses, MACs, host and service names replaced, payload layout kept;
   owner decision 2026-10-26).
2. **ROC gate.** The false `yes` rate over H0 and the false `no` rate over H1,
   measured per protocol, held by a test as a regression.
3. **Measured weights.** The `generated` and `assumed` sides are replaced by
   measured ones and the model number moves.

### 6.1 Where steps 1 and 2 stand (2026-10-26)

The corpus is `captures/corpus/`, described file by file in its
`corpus.json5`, and the ROC test is `crates/wz-capture/src/zenoh_corpus_tests.rs`:
no flow of an `other` file may read `yes`, no flow of a `zenoh` file may read
`no`, and every file's tally of the three words is pinned for both builds (with
and without lz4). The anonymiser is `scripts/lib/capture_anonymise.py`; its
selftest and `--verify-corpus` run in the pre-push static gate array.

It holds six zenoh 1.10.1 captures (TCP and UDP, from before the handshake and
joined mid-session, with and without lz4), three of an office Wi-Fi (DNS,
mDNS, SSDP), and the real implementations of MQTT (mosquitto), RTPS (ROS 2
Jazzy), CoAP (libcoap), SOME/IP (vsomeip) and HTTP/3 over QUIC versions 1 and
2 (aioquic) run in containers. Every zenoh flow reads `yes`; no flow of the
others reads `yes`. Every QUIC connection reads `undecided`, which is the
honest word: zenoh runs over QUIC as well, and a protected flow shows nothing
that tells the two apart.

A TCP flow of another protocol whose bytes never frame a unit carries nothing
model 1 weighs, and reads `undecided`: forty short MQTT connections do. A
framing that never takes, measured as the stream's desynchronisations without a
recovery, is evidence model 1 does not count yet; it is a check for step 3,
with its weights from this corpus.

**The corpus's first finding** was a false `no`: both flows of a compressed UDP
session joined mid-session read `no`. With no Init in the capture nothing told
the reader that every batch opens with a header byte, so it read that byte as a
message and every unit as undecodable. The reader now infers the header from
the bytes where no Init was seen (`FlowContext::batch_header`, the halves'
`batch_header` from field document revision 44): a unit that reads whole only
behind a header byte makes a datagram direction headed, a unit that reads whole
only as it stands makes it plain again, and a stream finds its framing again on
a chain of boundaries all in one of the two readings. The model did not move;
the evidence was misread.

What the header showed is also a negotiated value the handshake would have
stated: a batch header means the session negotiated compression, and a batch
that reads whole without one means it did not. From field document revision 45
each flow's `context.parameters` carries every negotiated value beside its
basis (`stated`, `inferred`, `conflicting`, `absent`), and `compression` is the
one the bytes can infer, with the counts it rests on per direction
(`PassiveSession::compression_reading`). On the corpus every capture that
holds the handshake states its compression and every one joined mid-session
infers the same value.

A busier network's own protocols are in the corpus too, from real
implementations in containers: DHCP between twelve clients and a server, NTP
between six clients and a server, LLMNR and WS-Discovery between a file server
and four askers. No flow of them reads `yes`.

Still to come for step 2: further zenoh versions and links on the zenoh side.

### 6.2 Model 2: measured weights, two sums (step 3, 2026-10-26)

The field document's revision 46 and the session table's revision 6 carry
model 2 (`crates/wz-capture/src/zenoh_evidence.rs`). Three things move.

**Two sums** (section 2): `log2_lr_millibits` is read for `yes`,
`log2_lr_no_millibits` for `no`, and each check carries `millibits` and
`no_millibits`. A check whose null chance is derived from field widths weighs
the same in both.

**Measured weights.** Every check's zenoh side but the SN steps', and the
null side of `unit_reading` and the new `stream_framing`, take their
probabilities from the counts of `captures/corpus/` (written out in
`model::measured`, re-measured by
`the_corpus_measures_the_counts_model_two_is_computed_from`, and turned into
the weights by `model_weights_are_their_stated_probabilities`):

- zenoh's chance of each failure is the one-sided 95% Clopper-Pearson upper
  bound on its count, and the confirming outcome takes the rest: 0 residual
  and 0 undecoded in 3062 units; 0 framings lost in 268 directions held from
  their start; 0 differing cookies in 264 echoes; 0 Init pairs of one kind in
  264; 0 other versions in 528 version headers. The zenoh files are 1.10.1
  routers and clients, an upstream 1.5.0 router, zenoh-pico 1.10.1 clients,
  240 short sessions captured for their handshakes, a lossy link, and a real
  link between two machines (an office Wi-Fi: TCP with small and 3000-byte
  samples, joined mid-session, UDP, and zenoh-pico);
- the `yes` sum's null chance of an outcome is the largest such upper bound
  over the null protocols (a unit read whole: mDNS, 13 of 36 units, bound
  0.51; a framing held: MQTT, 0 of 84 directions, bound 0.035);
- the `no` sum's is the average over the null protocols of each one's
  Jeffreys estimate, `(k + 1/2) / (n + K/2)`, a proper distribution.

| outcome | `yes` sum | `no` sum | model 1 |
|---|---|---|---|
| unit read whole | +964 | +3858 | +2603 |
| unit residual | -9998 | -8406 | -6745 |
| unit undecoded | -9998 | -9260 | -7000 |
| stream framing held | +4819 | +7393 | (none) |
| stream framing lost | -6491 | -6483 | (none) |
| cookie matched (8 bytes) | +63984 | +63984 | +63999 |
| cookie differing | -6470 | -6470 | -10000 |
| Inits of opposite kinds | +984 | +984 | +999 |
| Inits of one kind | -5470 | -5470 | -9000 |
| version of this reader | +7992 | +7992 | +8000 |
| another version | -7460 | -7460 | (none) |

The unit weight fell because the corpus's real mDNS reads a unit whole 36% of
the time where the generated mDNS model 1 was priced on did 16%: model 1's
weight claimed more than the bytes give, against a protocol the corpus holds.
The handshake violations weigh less than model 1's assumed `2^-10` gave them:
264 clean handshakes bound a failure only to about 1.1%, and a weight may not
claim more than the corpus shows.

**The SN steps stay assumed, as a tolerance.** How often a step breaks is a
property of the link, what it loses and reorders, and not of zenoh: the
loopback captures break nothing and `zenoh-udp-lossy.pcap`, a link dropping 5%
each way, breaks 6 steps of 110 (5.5%). A rate measured on either would
describe that capture's link. The assumed `2^-4` is the loss the test is built to tolerate,
and the lossy capture holds it there: both its flows read `yes`.

**`stream_framing`.** A stream direction is judged once, by what happened
first: a unit framed (held) or a desynchronisation this reader inferred
(lost); a hole the capture reported judges nothing
(`PassiveSession::first_framing`). It is weighed only for a TCP direction the
capture holds from its SYN: a tap that joins a zenoh stream later lands inside
a unit nearly always and loses the framing too, so there the observation says
how the capture began and not what the bytes are. Held from the start, zenoh
never lost it (0 in 268). The forty short MQTT connections lose it in both
directions and read `undecided` still: twenty-odd bytes a direction are too
few to say `no` at 2^-20, and that is the honest word.

What moved on the corpus: no zenoh flow and no other flow changed word; every
new zenoh flow reads `yes`. Of the repository's own captures, the seven-unit
raweth capture moved from `yes` to `undecided`: a version header, seven units
read whole and one SN break come to about ten and a half bits, and model 1's
crossing rested on the unit weight the real mDNS beats.

Still open after model 2: zenoh versions other than 1.10.1 and 1.5.0, links
other than loopback, one emulated lossy link and one Wi-Fi link, and the
null side only on the protocols the corpus holds (a busier LAN's DHCP, NTP,
LLMNR and WS-Discovery from real implementations are still to add).
