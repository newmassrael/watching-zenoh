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

**Several null protocols, one statistic.** H0 is a family (DNS, mDNS, SSDP,
RTPS, ...). For an outcome whose H0 probability differs across the family,
the weight uses the LARGEST probability any member shows. The statistic is
then at most the true ratio against every member, so the bound holds against
each member of the corpus at once. It does not hold against a protocol the
corpus does not contain; that is the limit the claim states and the reason
for section 6.

**The port is not evidence.** The thresholds are a statement about the bytes
under H0, and a prior odds from the port would move that statement by an
amount nobody has measured. A posterior beside the verdict needs base rates
per port, which only a corpus of real captures gives (section 6).

## 3. The observations (model 1)

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
