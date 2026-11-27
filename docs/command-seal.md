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

All of it is CBOR in the deterministic encoding of RFC 8949, section 4.2.1 (`cbor.rs`): every
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

Every item of the protected header has a fixed size, so it is 83 bytes. The payload is at most 60
bytes (a reset whose generation and counter each take eight), the Sig_structure at most 160 and
the whole object at most 216 (`MAX_SEALED_LEN`). A node opens one on its stack with no allocator.

### A worked object

The tests pin one object made outside the crate (`src/tests.rs`, `PINNED_SEALED_HEX`): a reset of
generation 7 for the peer `202122...2f` at the node `101112...1f`, counter 42, assembled by hand
from this document and signed by `openssl dgst -sha256 -sign` over its Sig_structure. Its key is
pinned as a PEM (`src/key.rs`), and the zid the crate derives from the COSE_Key equals what
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
take a replayed command once more. OSCORE meets the same loss with persisted state or a challenge
(RFC 8613, appendix B.1). The crate leaves the choice to the node: `ReplayWindow::iter` lists
every commander and its last counter, and giving them back to `accept` at start restores the
window. Which of the two a node uses is open (see the decisions at the end).

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

**A fixed-memory node** implements `Es256` over the PSA Crypto API of the TF-PSA library
`wz-tls-mbedtls` links. What it needs, which the port does not provide:

- one C entry point beside the channel's, e.g. `wz_tls_es256_verify(point, message, len,
  signature)`, that imports the point as a volatile key of type
  `PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)`, 256 bits, usage
  `PSA_KEY_USAGE_VERIFY_MESSAGE`, algorithm `PSA_ALG_ECDSA(PSA_ALG_SHA_256)` (PSA's import
  format for such a key is exactly the uncompressed point), calls `psa_verify_message` (PSA's
  signature format for ECDSA is exactly r then s, so neither side converts), and destroys the key;
- the build options `PSA_WANT_ALG_ECDSA`, `PSA_WANT_ECC_SECP_R1_256`,
  `PSA_WANT_ALG_SHA_256` and `PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY`, which a TLS 1.3 build that
  verifies a P-256 peer already enables;
- a Rust `impl Es256` over that entry point in `wz-tls-mbedtls`, so the codec crate stays free
  of any TLS library.

Not built, and not measured: what one verification costs in time and stack on a given MCU is
that image's measurement to make.

## How D16 consumes it

D16's monitor judges (subject, verb, object, context). A sealed command adds one subject,
`Commander::Sealed(&Zid)`, beside the commander a channel proves. The order on the node, for a
lifecycle query that carries a sealed command:

1. `verify_sealed(bytes, own_zid, &es256)`. A refusal refuses the request; the node does not
   fall back to the channel's commander, because a sealed command that fails is a claim that
   failed, not an absent one.
2. The sealed command must be the request: its verb is the key's verb (`open_passive` for a key
   `open/passive/<peer>`), its peer is the key's peer (`zid_from_key_text` of the peer chunk),
   its generation is the key's for a reset and absent otherwise, and its node is the key's node
   (`verify_sealed` checked it against the node's own). A mismatch refuses: a router must not
   move a sealed command onto another key.
3. The monitor judges `permits(verb, Commander::Sealed(&sealed.commander))`. A refusal takes no
   counter.
4. `Verified::take(&mut window)`. `Replay` or `WindowFull` refuses.
5. The effect, as for any commander.

A query that carries no sealed command keeps today's subject, the channel's commander. The window
lives with the node: on the fixed profile a static table of the size the declaration's sealed
grants need, on the heap profile the same type in the node's state.

## How the object travels (a proposal)

Proposed for the main session, not implemented here: the sealed command travels as the
**attachment** of the lifecycle query. The key keeps naming the node, the verb and the peer as
today, so routing and the key grammar are unchanged; the attachment is a query field the protocol
already carries end to end, and a router forwards it without reading it. A node reads it through
the query view it already has (`QueryView::attachment` in `wz_session_core::query_sink`). The
encoding has no framing of its own to add: the attachment is the 216 bytes or fewer of the object
itself, and its COSE tag (18) tells it apart from any other attachment. What the main session must
confirm before relying on it: that every router wz ships, and upstream's, forwards a query's
attachment unchanged to the queryable.

A commander seals with `seal` (or `examples/seal_command.rs`, which reads a PKCS#8 PEM and
prints the object in hex and the commander's zid) and sends a get on the lifecycle key with the
object as the attachment.

## Decisions for the owner

- **The window across a restart**: persist the window (`iter` and `accept`), or bind a command
  to the node's boot with a challenge the node hands out (OSCORE's Echo, RFC 8613 appendix
  B.1.2), which costs a round trip per command and keeps no state.
- **A sealed command that fails**: refused (proposed above), rather than judged as the channel's
  commander.
