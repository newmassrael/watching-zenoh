# Sealed lifecycle commands

A lifecycle command sealed by its commander's key, so the node it commands knows who sent it
whatever carried it: decision D17 of `docs/session-lifecycle-intent.md` (section 5b). The code is
the crate `crates/wz-command-seal`; this document is its format and the contract of its use.

## The problem and the model

A secure channel proves its next hop. A command that crossed a router reaches the node over the
router's link, and the zid that link proves is the router's, which stands for every commander
behind it. A grant to a commander behind a router is therefore unusable, and granting the router
instead would give it the authority of everyone it carries.

The textbook answer is to secure the object instead of the channel. OSCORE (RFC 8613) protects a
CoAP request end to end across proxies by wrapping it in a COSE object (RFC 9052) that the
endpoint verifies; the proxy forwards it and can neither read authority into it nor forge one
(RFC 8613, section 3). Its replay protection is a sender sequence number the recipient remembers
per sender (section 7.4). A sealed command is that model for one object: a COSE_Sign1 (RFC 9052,
section 4.2) over the command, signed by the commander, with a counter per commander that only
rises.

The commander needs no certificate. The object carries the commander's public key, and the node
derives the commander's zid from it: the zid of D1, the first sixteen bytes of the SHA-256 of the
key's DER SubjectPublicKeyInfo, the same zid a link that proved the same key reports
(`wz_session_core::credential_identity::zid_from_spki_der`, `scripts/lib/wz_node.py`
`zid_of`). The name certifies the key and the key certifies the name, as the self-certifying
pathnames of SFS (Mazieres, Kaminsky, Kaashoek and Witchel, 1999) do: no authority stands
between them, and a grant names the zid.

## The object

All of it is CBOR in the deterministic encoding of RFC 8949, section 4.2.1 (`crates/wz-command-seal/src/cbor.rs`): every
argument in the fewest bytes that hold it, every length definite, map keys in the bytewise order
of their encodings. There is exactly one encoding of a command, so the bytes the commander signed
are the bytes the node rebuilds the Sig_structure from, and two copies of one command cannot
differ.

```cddl
Sealed-Command = #6.18([            ; COSE_Sign1, tagged (RFC 9052, section 2)
    protected:   bstr .cbor Protected,
    unprotected: {},                ; empty: everything the node reads is signed
    payload:     bstr .cbor Payload, ; never detached
    signature:   bstr .size 64,     ; ES256: r then s, 32 bytes each (RFC 9053, section 2.1)
])

Protected = {
    1  => -7,                       ; alg: ES256
    14 => { 8 => { 1 => COSE_Key } } ; kccs (RFC 9528, section 3.5.2): cnf (RFC 8747) COSE_Key
}

COSE_Key = {                        ; RFC 9052 section 7, RFC 9053 section 7.1.1
    1  => 2,                        ; kty: EC2
    -1 => 1,                        ; crv: P-256
    -2 => bstr .size 32,            ; x
    -3 => bstr .size 32,            ; y (a bstr: the compressed form is refused)
}

Payload = [
    verb:    "open" / "open_passive" / "close" / "reset" / "status",
    node:    bstr .size 16,         ; the commanded node's zid, sixteen-byte form
    object:  [
        peer:       bstr .size 16,  ; the peer the verb acts on
        generation: uint / null,    ; a reset's generation; null for every other verb
    ],
    counter: uint,                  ; above every counter this commander sealed before
    ? echo:  bstr .size 16,         ; the node's echo, when the command repeats one refused for it
]
```

The signature is over the Sig_structure of RFC 9052, section 4.4, with no external data:

```cddl
Sig_structure = ["Signature1", protected: bstr, external_aad: h'', payload: bstr]
```

A zid is carried in the sixteen-byte form a key spells (the little-endian bytes of the id, zeros
to the end), never trimmed, so a zid has one spelling in the object. The verbs are the words of a
lifecycle key; a passive open is `open_passive` because the key spells it apart
(`open/passive/<peer>`, decision D10), and an object that bound only `open` could be carried to
the other mode.

### Where the key goes, and why

The key is a COSE_Key in the **protected** header, under `kccs` (14), the header parameter RFC 9528
(EDHOC) registered for a raw public key carried by value: a CWT Claims Set whose `cnf` claim
(RFC 8747) holds the COSE_Key. Two choices were open (a COSE_Key from which the SPKI is rebuilt,
or the SPKI bytes themselves), and each was weighed:

- **Protected, not unprotected.** In the protected header the signature covers the key. ECDSA
  admits a key substitution: given a signature and a message, a different public key can be
  computed under which the same signature verifies. With the key outside the signed bytes, a
  carrier could move a sealed command to that other key's zid; inside them, any other key changes
  the Sig_structure and the signature fails. The cost is nothing: the protected header is signed
  either way.
- **A COSE_Key, not the SPKI bytes.** COSE has a key representation of its own and a registered
  parameter that carries one, so a COSE tool reads the object without wz's help; the SPKI bytes
  would need a private label. The COSE_Key is also smaller: 80 bytes with the `kccs` and `cnf` maps around it, against 93 for
  the SPKI as a byte string. The SPKI is
  not lost: a P-256 key in the uncompressed form has exactly one DER SubjectPublicKeyInfo (RFC
  5480, section 2), the fixed 26 bytes `P256_SPKI_PREFIX` followed by `04 || x || y`, so the node
  rebuilds it (`spki_of_point`) and hashes the same 91 bytes a link would. Carrying the SPKI would
  have needed the same check the other way, since an SPKI with explicit curve parameters names
  the same key with other bytes; the COSE_Key has no such second spelling.

### Sizes

Every item of the protected header has a fixed size, so it is 83 bytes. The payload is at most 77
bytes (a reset whose generation and counter each take eight, carrying an echo), the Sig_structure
at most 177 and the whole object at most 233 (`MAX_SEALED_LEN`); without an echo each is 17 bytes
less. A node opens one on its stack with no allocator.

### A worked object

The tests pin one object made outside the crate (`crates/wz-command-seal/src/tests.rs`, `PINNED_SEALED_HEX`): a reset of
generation 7 for the peer `202122...2f` at the node `101112...1f`, counter 42, assembled by hand
from this document and signed by `openssl dgst -sha256 -sign` over its Sig_structure. Its key is
pinned as a PEM (`crates/wz-command-seal/src/key.rs`), and the zid the crate derives from the COSE_Key equals what
`wz_node.py` `zid_of` gives for that PEM (`ff05494985b357564f04d8a732497692`).

## Opening a sealed command

`open_sealed(bytes, this_node, &mut window, &es256)` checks, in this order, and refuses with the
first that fails:

| Check | Refusal |
| --- | --- |
| a head not in its deterministic form (an argument longer than needed, an indefinite length) | `NonCanonical` |
| anything not the format: another item or count, map keys out of order, an unknown verb, a generation on a verb that takes none or none on a reset, a zid not of 16 bytes, a detached payload, a non-empty unprotected header, an untagged object, bytes after it | `Malformed` |
| an algorithm other than ES256 | `Algorithm` |
| a key other than an EC2 P-256 key with both coordinates of 32 bytes | `Key` |
| a node zid other than this node's | `WrongNode` |
| a signature that does not verify under the carried key | `BadSignature` |
| a counter not above the commander's last | `Replay { last }` |
| a commander the window has no counter for and no room for | `WindowFull` |

The decoding refusals interleave in the order the bytes are read. The counter is taken only after
the signature verified, so a forged object moves no counter.

`verify_sealed` and `Verified::take` are the same two steps apart. They exist because the key is
self-certifying: anyone can make a key and seal a command that verifies under it. A node that took
the counter of every verified command would give a slot of its window to every key that wrote to
it, and a full window refuses the commanders it does grant. So a node judges the commander between
the two steps and takes the counter only of a command it permits (below).

## The replay window

`ReplayWindow<N>` holds the last counter of up to `N` commanders, in a fixed table with no
allocator. A counter above the commander's last is taken; any other is `Replay`. This is the
replay window of RFC 8613, section 7.4, narrowed to its high-water mark: a lifecycle command is
rare and its commander waits for the answer, so the window OSCORE keeps for messages arriving out
of order is not needed. A commander with two commands in flight gives the later counter to the one
it sends later; if the other arrives second it is refused and is sent again with a new counter.

When the table is full a new commander is refused with `WindowFull`, and no commander is evicted:
forgetting one would let every command it ever sealed be replayed once more. Sized to the
commanders the node's declaration grants, and filled only with commanders the node permits, a
window never fills in a correct deployment, so `WindowFull` names a declaration that grants more
commanders than the window holds.

**A restart.** The window is memory, so a node that restarts has forgotten its counters and would
take a replayed command once more. OSCORE recovers a lost replay window with the echo (RFC 8613,
appendix B.1.2), and `Freshness<N>` (`crates/wz-command-seal/src/fresh.rs`) does so:

- **Echo** (appendix B.1.2; RFC 9175, section 2), what every node does: when it starts it draws an
  echo of sixteen bytes from its entropy (`Freshness::echo`). A verified command of a commander the
  window holds no counter for is refused with `EchoRequired { echo }` unless its payload carries
  that echo; the commander seals the command again, under a new counter, with the echo as the
  payload's fifth item, and that command is taken and starts the commander's counter. A command
  sealed before the start cannot carry an echo drawn after it, so none is taken twice, and the
  node keeps nothing across the start. The echo of a commander the window holds is not read: its
  counter already refuses what it sealed before. It costs one round trip per commander per start.
- **A persisted window**, which the crate still offers (`Freshness::persisted`, the fixed
  profile's `FixedSeal::start_persisted`), is not OSCORE's: appendix B.1.1, cited here before, is
  the sender's sequence number, and B.1.2 recovers the window with the echo alone. A copy of the
  window older than the last command taken would accept that command again. Ruling D20 removes
  it; the commander, as the sender, keeps its own counter as B.1.1 says.

`Freshness::check` answers whether a command would be taken, taking nothing, and
`Freshness::take` takes it after the same check.

## Ports

Verification and signing are ports, so a node uses the primitives it already links:

- `Es256::verify(point, message, signature) -> bool`: ECDSA over P-256 with SHA-256 of
  `message`; `point` is the 65-byte uncompressed point, `signature` is r then s. A point that is
  not on the curve must verify nothing.
- `Es256Signer`: the signer's point and `sign(message)`.
- SHA-256 for the zid is the `sha2` crate, which every profile already links for the zid of a
  link's key.

**The host** has `RingEs256` and `RingSigner` over `ring` (feature `ring`, on by default):
`ECDSA_P256_SHA256_FIXED` verifies, `ECDSA_P256_SHA256_FIXED_SIGNING` signs, and `RingSigner`
reads a PKCS#8 document or makes a key. A fixed-memory build turns the feature off
(`default-features = false`) and links no `ring`.

**A fixed-memory node** verifies over the PSA Crypto API of the TF-PSA library `wz-tls-mbedtls`
links: `wz_tls_mbedtls::es256::PsaEs256` (feature `es256`, `crates/wz-tls-mbedtls/src/es256.rs`)
over the C entry point `wz_tls_es256_verify` (`crates/wz-tls-mbedtls/csrc/wz_tls.c`). It imports
the point as a volatile key of type `PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)`, 256
bits, usage `PSA_KEY_USAGE_VERIFY_MESSAGE`, algorithm `PSA_ALG_ECDSA(PSA_ALG_SHA_256)` (PSA's
import format for such a key is exactly the uncompressed point), calls `psa_verify_message`
(PSA's signature format for ECDSA is exactly r then s, so neither side converts) and destroys the
key; a point the import refuses verifies nothing, and a call before the library started verifies
nothing. It needs `PSA_WANT_ALG_ECDSA`, `PSA_WANT_ECC_SECP_R1_256`, `PSA_WANT_ALG_SHA_256` and
`PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY`, which the channel's TLS 1.3 with a P-256 peer already needs:
the build `vendored` makes states them in `crates/wz-tls-mbedtls/config/wz_tls_crypto_config.h`,
and a Zephyr image states them in its own configuration (`CONFIG_PSA_WANT_ALG_ECDSA`,
`CONFIG_PSA_WANT_ECC_SECP_R1_256`, `CONFIG_PSA_WANT_ALG_SHA_256`,
`CONFIG_PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY`). The echo is drawn from the same library's generator
(`es256::random_echo`, `psa_generate_random`). The codec crate stays free of any TLS library.

Not measured: what one verification costs in time and stack on a given MCU is that image's
measurement to make.

## How the monitor consumes it

D16's monitor judges (subject, verb, object, context). A sealed command adds one subject,
`Commander::Sealed(&Zid)`, beside the commander a channel proves. The order on the node, for a
lifecycle query that carries a sealed command, is written once for both profiles
(`crates/wz-session-core/src/sealed_command.rs`, `claim`):

1. `verify_sealed(bytes, own_zid, &es256)`. A refusal refuses the request; the node does not
   fall back to the channel's commander, because a sealed command that fails is a claim that
   failed, not an absent one.
2. The sealed command must be the request: its verb is the key's verb (`open_passive` for a key
   `open/passive/<peer>`), its peer is the key's peer (`zid_from_key_text` of the peer chunk),
   its generation is the key's for a reset and absent otherwise, and its node is the key's node
   (`verify_sealed` checked it against the node's own). A mismatch refuses
   (`NotTheRequest`): a router must not move a sealed command onto another key.
3. `Freshness::check`: a replay, a window with no room, or a commander with no counter and no
   echo refuses, taking nothing.
4. The monitor judges the request with `Commander::Sealed(&sealed.commander)`. The entry point
   judges the node through `SealedNode`, whose monitor holds the `Admission` that takes the
   counter: `Monitor::decide` asks it only after a grant permits the commander, and a refused
   take turns the permit into `Refusal::NotFresh`. A monitor given no admission refuses every
   sealed commander so (fail-safe). An object no grant permits therefore takes no counter and no
   slot of the window.
5. The effect, as for any commander.

A query that carries no attachment keeps today's subject, the channel's commander. A query that
carries an attachment on a node given no verifier, or built without `sealed-commands`, is
refused as `NotVerified`. The window lives with the node: on the heap profile a
`SealedCommands<E, N>` in the node's `LifecycleQueries` (`with_seal`), on the fixed profile a
`FixedSeal<E, N>` in a static behind the runtime's critical section, handed to the verbs'
queryable with `VerbLegs::verify_sealed_with` and started with the node's zid and an echo once
the node knows its zid (`FixedSeal::start`). An admin node's `Verbs` and a node that binds only
the open verb verify none.

## How the object travels

The sealed command travels as the **attachment** of the lifecycle query. The key keeps naming the
node, the verb and the peer as today, so routing and the key grammar are unchanged; the
attachment is the object itself, 233 bytes or fewer, with no framing of its own. A node reads it
through the query view it already has (`QueryView::attachment`).

A router forwards it unchanged. Upstream's attachment of a query is a field of the query body
(`commons/zenoh-protocol/src/zenoh/query.rs` @ `pub ext_attachment: Option<ext::AttachmentType>,`),
and its router hands a routed request on with that body cloned
(`zenoh/src/net/routing/dispatcher/queries.rs` @ `payload: msg.payload.clone(),`). wz's router
clones the whole request and rewrites its source, its key and its id alone
(`crates/wz-runtime-tokio/src/router_forward.rs` @ `let mut carrier = request.clone();`).

**The reply.** A query whose sealed command is refused before the monitor is answered as every
lifecycle refusal is, one JSON document with the packed id of `application/json`, under the key
that was asked: `{"verdict":"refused","reason":"<words>"}`, the words naming the refusal
(`SealRefused::words`). Two carry what the commander needs: a replay adds the commander's last
counter, `"last":N`, and the challenge of a node that has just started adds its echo,
`{"verdict":"refused","reason":"the sealed command must carry this node's echo","echo":"<32
lowercase hex digits>"}`, the echo's sixteen bytes in order, which the commander puts back as the
payload's fifth item. A request the monitor refuses is answered in the verb's own refusal
(`"this node does not permit closing the session with that peer"`), whoever its subject was.

A commander seals with `seal` (or `crates/wz-command-seal/examples/seal_command.rs`, which reads
a PKCS#8 PEM, takes the echo a refusal handed out as `echo=<hex>`, and prints the object in hex
and the commander's zid) and sends a get on the lifecycle key with the object as the attachment.

## Decisions (owner, 2026-11-28)

The questions this section left open are ruled in `docs/session-lifecycle-intent.md`, 5c:

- **The window across a restart**: the echo alone, on every node (D20). The persisted window is
  removed: it is not OSCORE's recipient method, and a rolled-back copy accepts a replay.
- **The window's size**: one slot per commander the declaration grants, made with the policy on
  both profiles; `WindowFull` and the heap profile's bound of 64 go (D19).
- **A sealed command that fails**: refused by name, never judged as the channel's commander
  (unchanged).
- **The reply**: every reply to a command whose signature verified is a COSE_Sign1 under the
  node's key, bound to the commander's zid and the request's counter (D21). A plain reply let a
  router forge `"last"` and push a commander's counter to the top of its range.
- **`configure`**: a sealed verb whose object is the written key and the SHA-256 of the value,
  carried as a lifecycle query with the value as its payload (D22); a secure image grants it by
  name only (D23).
