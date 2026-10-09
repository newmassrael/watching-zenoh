/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * R311y586 (A7) — the C ABI over wz's dissection surface.
 *
 * MEMORY RULE, and it is the whole contract: every char* this library
 * returns is owned by this library. Release it with wz_dissect_string_free.
 * Nothing else crosses the boundary allocated, no callbacks run, and no
 * handle outlives the call that made it.
 *
 * R2102 (ABI 11) REVISED THAT LAST CLAUSE, and this paragraph is the
 * revision rather than a note beside it. It used to be true without
 * exception; there is now exactly ONE exception and it is named:
 *
 *   - every char* is still owned by this library and still released with
 *     wz_dissect_string_free;
 *   - NO CALLBACKS RUN. Unchanged, and the live door below is built to keep
 *     it: records are written into a buffer YOU own and sized
 *     (wz_dissect_live_drain), never handed to a function pointer of yours
 *     that this library would call. A callback is a piece of your control
 *     flow executing inside this library, on a stack it owns, and that is
 *     what this ABI declines to admit;
 *   - ONE KIND OF HANDLE OUTLIVES ITS CALL: the opaque wz_dissect_live made
 *     by wz_dissect_live_open and released, exactly once, by
 *     wz_dissect_live_close. It is not thread-safe. Use one handle from one
 *     thread at a time, and open a handle per tap rather than sharing one.
 *
 * R2205 (ABI 14) DID NOT REVISE IT AGAIN, and that is stated here rather than
 * left to be inferred, because wz_dissect_live_message_bytes is the first door
 * in this file handing back something that is neither a char* nor a
 * fixed-layout record -- so it is the one a reader would expect to have moved
 * the rule. BYTES ARE NOT A STRING: wz_dissect_string_free is not their shape,
 * and a door that allocated them would have added a second thing to give back.
 * It hands them into a buffer YOU own and sized instead, exactly as
 * wz_dissect_live_drain hands records, so the three clauses above stand word
 * for word. Nothing new crosses this boundary allocated.
 *
 * WHY IT COULD NOT STAY: a live tap is a dissection kept alive between
 * packets. A door that could not keep one would re-read the whole link on
 * every call, which is not a tap, it is a file read repeated. Widening the
 * sentence quietly was never available -- the clause is load-bearing, and
 * the callback half of it is the ground a previously proposed
 * callback-registration door was refused on. So the rule is restated here,
 * and wz_dissect_abi_version moves for the memory rule exactly as it moves
 * for a symbol.
 *
 * THE LIVE RECORDS ARE BINARY, alone among this library's outputs. That is
 * not a retreat from the self-describing-document design below: these
 * records carry no walker output. They are the fixed scalars that say a
 * message arrived -- when, on which flow, which way, how long, what kind --
 * and a live tap renders them at line rate, where a JSON round trip per
 * message is work proportional to the traffic for eight fields. A consumer
 * wanting the field TREE of one message still asks for it by name.
 *
 * THE JSON SHAPE IS NOT FROZEN. Field names are wz's walker names and may
 * gain siblings as walkers are added. Read by name and tolerate unknown
 * keys — that forward-compatibility is the reason this ABI hands back a
 * self-describing document instead of a struct tree. wz_dissect_abi_version
 * moves when a SYMBOL or the memory rule changes, never when the JSON gains
 * fields.
 *
 * EVERY DOCUMENT SAYS ITS OWN REVISION, and that is a different number from
 * the one above. Each one OPENS with
 *
 *     {"document":{"name":"census","revision":<N>}, ...}
 *
 * so a consumer reads it before parsing the body. R2180 struck a literal `1`
 * from that line: the census had been at revision 4 for two rounds and this
 * example still showed the number it shipped with, which is the same defect
 * open-debt item 554 is about one paragraph long. ASK the document; the number
 * here would only ever be a copy. (The envelope carries one more key for a
 * document that declares planes -- see R2180 below.) The names are "census",
 * "fields", "summary", "readable_surfaces", "selector_diagnose",
 * "declarations_diagnose", "keyexpr_diagnose", "declarations_from_proto", "e2e_wrap", "e2e_open", "proto_encode", "transport_build", "selection", "retention" and "health" — one per door group, because a consumer calls the
 * door it wants and a single library-wide number would tell a reader of the
 * census that a document it never calls had moved.
 *
 * WHY IT EXISTS: reading by name is safe against ADDED keys and is not safe
 * against a key that is RENAMED or REMOVED, and wz_dissect_abi_version is
 * defined not to move for either. The document revision is the number that
 * does. A key never leaves without the revision before it having emitted it
 * alongside its replacement, so a consumer pinned to a revision always has one
 * revision's notice: read the revision, and refuse — or re-check — a value you
 * were not written against.
 *
 * R2175 — AND IT MOVES FOR A WIDENED VALUE VOCABULARY, which is a second break
 * the two rules above left with no number. Some keys carry a string drawn from
 * a CLOSED SET this library owns, and a consumer switches on it. When that set
 * gains a word, no key is renamed and none is removed, so every rule above is
 * satisfied while the switch falls through to its own default — on a record the
 * library described perfectly well. Measured: R2170 added `not_on_the_wire` as
 * an eighth `payload_decode.state`, REPLACING what had been reported as
 * `no_payload` for SHM records, and nothing moved.
 *
 * ⚠ THE ASYMMETRY IS THE OPPOSITE OF THE KEY SET'S, and reading it the other
 * way round is the mistake to avoid. For KEYS the dangerous direction is
 * removal and an addition is safe. For VALUES the dangerous direction is
 * ADDITION — a word that leaves only makes one of your arms unvisited, while a
 * word that arrives is one your switch has no arm for. So there is no
 * announce-then-drop dance for values: the revision itself IS the notice, and
 * it moves in the round the word is added.
 *
 * WHICH KEYS THOSE ARE IS A QUESTION YOU CAN ASK. Every such key carries
 *
 *     @values <document> <key>
 *
 * in its own comment block here, and wz_dissect_readable_surfaces reports the
 * same set AT RUNTIME under `value_families`, with the words. A list copied
 * into your own switch ages the moment this one grows, which is the argument
 * `payload_field_types` already makes one surface over; comparing what you were
 * written against with what this build reports is how a program says "there is
 * a state I do not know" instead of discovering it as a fallthrough.
 * `the_header_and_the_library_agree_about_every_value_family` holds both
 * directions, so a family added later cannot arrive undeclared and a marker
 * cannot outlive the family it names.
 *
 * THE CENSUS DOCUMENT'S FIVE, at revision 4 -- which moved for these and for no
 * key, the first revision in this ABI to do so:
 *
 *     `kind`          on an interest row: `subscriber`, `queryable` or
 *                     `liveliness_token`
 *     `mode`          the mode an Interest was asked in: `final`, `current`,
 *                     `future` or `current_future`
 *     `offset_space`  which coordinate the anchors on this row are in:
 *                     `packet` (an index into the file) or `stream_byte` (an
 *                     offset into one direction's reassembled stream). SWITCH
 *                     on it -- the two are not the same number and adding a
 *                     span to the wrong one is silent.
 *     `asker`,        which end of the flow: `a` or `b`
 *     `declarer`
 *     `cause`         on a `keyexprs.unresolved[]` row: WHY the reference did
 *                     not resolve. `no_declaration` -- this capture holds the
 *                     whole session and nothing on it ever declared the id, so
 *                     the gap is real. `no_session` -- this flow showed no
 *                     handshake, so the observer could not say which session
 *                     it belongs to, and a SIBLING LINK of that session may be
 *                     carrying the declaration. SWITCH on it: the two send you
 *                     to different places, and a capture started mid-session
 *                     yields the second in bulk.
 *
 * @values census kind
 * @values census mode
 * @values census offset_space
 * @values census asker
 * @values census declarer
 * @values census cause
 *
 * The field document carries `offset_space` and `direction` with the same two
 * vocabularies, and they are declared SEPARATELY there -- a consumer pins the
 * two documents separately, so each says its own words at its own revision.
 *
 * @values fields offset_space
 * @values fields direction
 *
 * Round 2447 -- AND WHICH LINK A FLOW WAS READ OFF, at census revision 8 and
 * field-document revision 7 (the SPELLING rule below moved again at census 9 /
 * fields 8; see the second warning). Every flow object in both documents
 * carries
 *
 *     "flow":{"low":{"addr":"30:03:c8:37:25:a1","port":0,"family":null},
 *             "high":{"addr":"aa:bb:cc:dd:ee:ff","port":0,"family":null},
 *             "link":"raweth"}
 *
 *     `link`         which kind of link the two endpoints were read off:
 *                    `tcp`, `udp`, `raweth` (pico's L2 link, whose endpoints
 *                    are MACs and whose ports are always zero), `vsock` (the
 *                    endpoints are context ids) or `serial` (a point-to-point
 *                    line with no addressing at all, whose key is empty in
 *                    every field).
 *
 * ⚠ READ `addr` THROUGH IT. The spelling depends on the link, and there is one
 * rule per kind rather than one rule with exceptions:
 *
 *     `tcp` / `udp`  an IP address -- dotted quad for four bytes, RFC 5952
 *                    text for sixteen (`fe80::1`, `2001:db8::1:0:0:1`).
 *     `raweth`       six colon-separated MAC octets, lower case.
 *     `vsock`        the AF_VSOCK context id in DECIMAL, so `addr` and `port`
 *                    reassemble into the `vsock/<CID>:<PORT>` locator the
 *                    endpoint was configured with.
 *     `serial`       the empty string. A serial line has no addressing, so
 *                    there is no address to spell; `port` is zero for the same
 *                    reason.
 *
 * Before census revision 8 a raweth endpoint's six bytes went through a "not
 * four, therefore IPv6" branch and printed as `3003:c837:25a1`, which reads as
 * a truncated address and is why this key exists. The consumer that asked for
 * it asked specifically that it NOT be inferred from the endpoint shape, and it
 * is not: the library records the link kind where the frame is decapsulated.
 *
 * ⚠ AND `vsock` MOVED AT CENSUS REVISION 9 / FIELD-DOCUMENT REVISION 8, with no
 * key changing. That same inference reached one family over: an 8-byte
 * little-endian context id read as four hex groups, so cid 2 printed
 * `"addr":"200:0:0:0"` -- a well-formed IPv6 address, and therefore the kind of
 * wrong a consumer cannot detect. It now prints `"addr":"2"`. A consumer that
 * parsed the old form has nothing in the key set to notice the change by, which
 * is exactly what the revision number is for: pin it, and refuse a document
 * whose revision you have not read this paragraph for.
 *
 * ⚠ AND AN IPv6 `addr` MOVED AT CENSUS REVISION 14 / FIELD-DOCUMENT REVISION
 * 18, with no key changing. Sixteen bytes were written as eight hex groups
 * with no `::`, so the loopback read `"addr":"0:0:0:0:0:0:0:1"`. They are RFC
 * 5952's text now -- lower case, no leading zeros, the longest run of two or
 * more zero groups written `::` (the first of two that tie), a single zero
 * group written `0` -- which is what zenohd logs: `"addr":"::1"`,
 * `"fe80::1"`, `"2001:db8::1:0:0:1"`. A consumer that JOINS an `addr` to an
 * address it took from a router's own text by string finds the match now; one
 * that STORED the old text holds a spelling no other surface prints. An IPv4
 * endpoint, a MAC and a vsock context id read as before, and an IPv4-mapped
 * address is written in the mixed form (`::ffff:192.0.2.1`), which RFC 5952
 * leaves alone. Nothing in the key set changed, so the revision number is the
 * whole notice.
 *
 * AND `family` ARRIVED AT CENSUS REVISION 15 / FIELD-DOCUMENT REVISION 20: one
 * key on each endpoint, beside `addr` and `port`.
 *
 *     "low":{"addr":"fe80::1","port":43210,"family":"ipv6"}
 *
 *     `family`       `ipv4` or `ipv6` for an endpoint read off a `tcp` or a
 *                    `udp` link, and `null` for one that was not (`raweth`,
 *                    `vsock`, `serial`), which have no address family to name.
 *
 * Why it is on the endpoint: `addr` and `port` are separate keys and joining
 * them is the consumer's, and once an IPv6 address is compressed the join is
 * ambiguous -- `fe80::1` and 7447 written together read as the address
 * `fe80::1:7447`. Both ends of a flow are always the same family, and the word
 * is written on each anyway, so a reader formatting one endpoint does not need
 * the flow around it. READ it rather than inferring it from the colons in
 * `addr`: that would be a second decoder of a fact the library already holds,
 * and a MAC has colons too and is not IPv6. The key is an addition, so a
 * consumer pinned to an earlier revision loses nothing.
 *
 * @values census link
 * @values fields link
 * @values census family
 * @values fields family
 *
 * R2182 -- AND THE FIELD TREE'S OWN DISCRIMINANT, at field-document revision 3:
 *
 *     `kind`          what a walked field holds, and therefore WHICH KEY comes
 *                     with it. `bits`, `flag`, `uint`, `bytes`, `zid`, `text`
 *                     and `label` each carry `value`; `nested` carries
 *                     `fields`, an array of further field objects; `opaque`
 *                     carries NEITHER -- its span is the whole answer, and it
 *                     means this build knows where the structure is and did
 *                     not walk into it, which is not the same as there being
 *                     nothing there.
 *
 * `zid`, at field-document revision 17: a field named `zid` is an
 * IDENTITY and no longer opaque `bytes`. Its `value` is zenoh's spelling of the
 * id -- the little-endian id read as a `u128`, so the wire bytes REVERSED, with
 * a leading zero nibble dropped -- which is what zenohd logs, what a config
 * file's `id` takes, and what the census and the `zid ==` selector now use. Its
 * span is unchanged and still names the RAW WIRE BYTES: highlight the cells the
 * span covers, and read the identity text beside them. A switch on `kind` that
 * was written against the eight earlier words is no longer exhaustive; show an
 * unknown word rather than dropping the field.
 *
 * @values fields kind
 *
 * ⚠ READ THE COMPANION KEY OFF THE WORD, not off the arms that happen to
 * share one. `opaque` is the arm no capture in the wz tree produces, so a
 * consumer whose goldens come from real traffic meets it first in the field --
 * which is how the surface that asked for this vocabulary came to be missing
 * it. It is also why the words are reported from the library's own variant
 * walk rather than from anything observed.
 *
 * ⚠ AND IT IS NOT THE CENSUS `kind`. Same spelling, different closed set,
 * different document: on an interest row the word is `subscriber`, `queryable`
 * or `liveliness_token`.
 *
 * R2223 -- AND THE MESSAGE NAMES, at field-document revision 5. The third
 * near-namesake above used to end this paragraph as an exception -- "the
 * message kind on a record row travels under `name` and is not a member of
 * either family" -- and that sentence was the item. It is now a family of its
 * own.
 *
 * WHY IT COULD NOT BE `name`. A walked message row carries `name`, and so does
 * every node inside its tree, at every depth: `Push` and `keyexpr` and `sn`
 * arrive under one key. That set is open by construction, so no revision could
 * declare it, and a program splitting traffic by message had to test an open
 * set against a list it wrote by hand. Ours was in a crate you cannot link, and
 * it shipped for months missing `Join` -- every witness read a TCP unicast
 * capture and a Join is a multicast announcement, so nothing revealed the hole.
 *
 * WHAT ARRIVES INSTEAD. Every walked message row carries
 *
 *     "carried":[{"message":"Frame","start":0,"end":41,"keyexpr":null},
 *                {"message":"Push","start":3,"end":41,
 *                 "keyexpr":"demo/sensor/temp"}]
 *
 * -- the transport message this row is, then every network message batched
 * inside it, each with the span its bytes occupy in the row's own coordinate
 * space (`start` and `end` are message-relative, exactly as they are inside
 * `fields`; the row's `message_at` or `packet` says where the message itself
 * sits). The word is read from the MID BYTE through the library's own message
 * type, not from the tree's node names.
 *
 *     `message`      which message: `Init`, `Open`, `Close`, `KeepAlive`,
 *                    `Frame`, `Fragment`, `Join`, `Oam` on the transport, and
 *                    `Push`, `Request`, `Response`, `ResponseFinal`,
 *                    `Interest`, `Declare` inside a `Frame` batch. `Oam` is
 *                    both -- it has a transport MID and a network one.
 *                    `Scout` and `Hello` are the SCOUTING space's, each on a
 *                    datagram row of its own (revision 10, below).
 *
 * R2440 -- AND THE KEY THAT MESSAGE TRAVELLED UNDER, at field-document
 * revision 6.
 *
 *     `keyexpr`      the RESOLVED key expression, or `null`.
 *
 * RESOLVED, which is the whole of it. The wire carries `(id, suffix)`, and this
 * build folds every `Declare` of a key id as it walks -- in frame order, ahead
 * of any display cap -- so an entry naming its key by id alone reports the
 * literal that id was bound to. Reading the suffix yourself does NOT give you
 * this: a message carrying both an id and a suffix has the id's base PREPENDED,
 * so the suffix alone reports `/temp` for a record published under
 * `demo/sensor/temp` -- a WRONG key rather than a missing one, which for
 * anything replaying the capture is traffic sent to the wrong topic on a live
 * network.
 *
 * UNCONDITIONAL. It does not depend on declaring a payload format, and until
 * revision 6 it did: the value left this library only inside `payload_decode`,
 * so a consumer with no format to declare could reach it only by handing over a
 * decoder mapping it would never read. A key expression is a property of the
 * message and has nothing to do with how its bytes are encoded.
 *
 * `null` means no key was named on this entry, and there are three ways to get
 * it, all of them honest: the message carries no `WireExpr` at all (an `Init`,
 * a `KeepAlive`); this capture holds no `Declare` binding the id it used, which
 * is what a capture begun mid-session looks like; or the two id spaces bind the
 * same id to different literals, where a guess would be worse than a refusal.
 * It is emitted rather than omitted so a missing key cannot be confused with a
 * build that stopped reporting one.
 *
 * ⚠ Those three were one silence until revision 9, and the key below is what
 * separates them. Do not tell them apart by inspection.
 *
 * R2458 -- AND WHY, at field-document revision 9.
 *
 *     `keyexpr_cause` `"no_declaration"`, `"no_session"`, or `null`.
 *
 * Read it whenever `keyexpr` is `null`. `null` here means there was no key to
 * resolve, so nothing failed -- the `Init` and `KeepAlive` case above, and the
 * batching `Frame` two paragraphs down. A WORD means a reference WAS made and
 * this reader refused it:
 *
 *     `no_declaration`  the session is named and nothing on it ever declared
 *                       this id. The declaration is not in this capture: it
 *                       predates the file, or it was in a batch this build
 *                       could not read, or the sender referenced an id it never
 *                       minted.
 *     `no_session`      no session is known for the flow this reference
 *                       travelled on, because this capture never saw its
 *                       handshake. The declaration may well be here, one link
 *                       over -- so RE-CAPTURE from before the session opens
 *                       rather than searching for a missing `Declare`.
 *
 * The two send you to opposite places, which is why they are not one count.
 * The same enum reaches the census document under `cause`, at its revision 11.
 *
 * @values fields keyexpr_cause
 *
 * AND WHICH ID, at field-document revision 24.
 *
 *     `keyexpr_id`  the numeric id the message referenced, or `null`.
 *
 * It sits on every entry of `carried` and of `above_transport.carried`, beside
 * `keyexpr` and `keyexpr_cause`, and it is a number exactly when
 * `keyexpr_cause` is a word: a key that resolved, and a message that
 * referenced none, have no id to report, and it is `null` for both. It is the
 * id as the message wrote it -- not remapped between the sender's table and
 * the receiver's, and without the suffix a reference may add after it. A list
 * that has no key to print for a row prints this where it would have printed
 * the key (`id 7`), and it comes from this array because every row of such a
 * list does. It is an integer a JSON number could misread, so it takes the rule
 * of the paragraph on integers below. Like `keyexpr` and `keyexpr_cause` it can
 * change in an issued row (see the list of revisable cells).
 *
 * ⚠ REVISION 9 ALSO MOVED WHICH REFERENCES RESOLVE AT ALL, under a stationary
 * `keyexpr`, and no `value_families` row can say so. Until it, this document
 * folded a keyexpr id space PER FLOW, while a zenoh session with
 * `transport/unicast/max_links` above 1 spreads one id space over several
 * 5-tuples: a `Declare` that went out on the first link left every reference on
 * the second reported as `null`. They now share the capture's one space, keyed
 * by the session the handshakes named. If you cached "this id is unresolvable
 * in this capture" from revision 8 or earlier, that negative may be wrong --
 * the value can only have gone from `null` to a literal, never the other way.
 *
 * A transport message that BATCHES gets `null` here even when the records
 * inside it name keys: those keys belong to the records, each of which has its
 * own entry. One `Frame` can carry several messages that share no key.
 *
 * AND WHAT THE MESSAGE SAYS ABOUT ITS PAYLOAD, at field-document revision 28.
 *
 *     `payload`  {"start":N,"end":N,"encoding":"...","shm_descriptor":false},
 *                or `null`
 *
 * It follows the key on every entry of `carried` and of
 * `above_transport.carried`, WHATEVER YOU DECLARED: it needs no format. `null`
 * means the message has no payload slot at all -- a delete, a query with no
 * body, a declaration, and every transport message. Otherwise `start` and
 * `end` are the payload's byte range in the entry's own coordinates (the joined
 * buffer's, for a record of a reassembled chain), so the bytes are
 * `[start, end)` of the same buffer the entry's own `start` and `end` index.
 * `encoding` is the encoding the sample itself carried, spelled as zenoh prints
 * one -- `application/json`, `application/protobuf;pkg.Msg` with a schema,
 * `unknown(N)` for an id this build's table does not hold -- and `null` when
 * the message carried none, which on the wire means the default `zenoh/bytes`;
 * a sample that names `zenoh/bytes` explicitly says so, and is not `null`.
 * `shm_descriptor` is true when the range holds an SHM descriptor, an address
 * and not content: the data it stands for never crossed this wire (compare the
 * `not_on_the_wire` state below). A payload sent as slices reports the range of
 * its first descriptor when it has one, and of all its slices otherwise.
 *
 * It is on the ENTRY and not on the row because a row is one transport message
 * and a `Frame` batches several network messages that need not share a key, a
 * payload or an encoding; the entry is the smallest object that names ONE
 * message, so its key, its cause and its payload are read from it together. A
 * transport message's own entry says `null`: what a `Frame` carries is its
 * records', and a `Fragment`'s bytes are a piece of a batch and not
 * application data. The range is derived from the message's bytes and does not
 * change in an issued row.
 *
 * AND WHICH BODY THE MESSAGE CARRIES, at field-document revision 33.
 *
 *     `body`  the name of the body the message carries, or `null`
 *
 * It follows `message` on every entry of `carried` and of
 * `above_transport.carried`. `message` is the OUTER message; the body it
 * carries is what tells two entries of one message apart,
 * above all a declaration that names no key (`decl_final`,
 * `undecl_subscriber`), which no other key of the entry distinguishes. Until
 * revision 33 the body was a branch of the row's `fields` tree and nowhere in
 * the entry.
 *
 * The value is the NAME of the direct branch of the message's own node of the
 * `fields` tree that carries the message's own `mid` -- the same word the tree
 * prints, since the tree is built with the vocabulary this key is declared
 * from, not a second table beside it. Every message that has a body says one of
 * these:
 *
 *     `Push`       `put`, `del`
 *     `Request`    `query`, and `put` or `del` where the request carries one
 *     `Response`   `reply`, `err`
 *     `Declare`    `decl_kexpr`, `undecl_kexpr`, `decl_subscriber`,
 *                  `undecl_subscriber`, `decl_queryable`, `undecl_queryable`,
 *                  `decl_token`, `undecl_token`, `decl_final`
 *
 * THE NAME IS THE BRANCH'S AND NOTHING FINER. A `Response` that carries a reply
 * says `reply`; the `put` or `del` that reply carries is a branch of the
 * `reply` branch, and this key does not look into it. The branch an `Interest`
 * nests under the name `body` in the tree (its restriction) is not a body in
 * this sense, because it carries no `mid`.
 *
 * `null` for a message with no such branch: every transport message (a
 * `Frame`, a `Fragment`, an `Init`, an `Open`, a `KeepAlive`, a `Close`, a
 * `Join`, a `Scout`, a `Hello`), a `ResponseFinal`, an `Oam`, and an
 * `Interest`. The key is on EVERY entry, as `keyexpr` and `payload` are, so a
 * `null` here says the message has no body and cannot be a build that stopped
 * reporting one; a document of revision 32 or earlier has no `body` key at all,
 * and the revision tells that apart. Nor does the message word decide whether
 * the key arrives: `message` stays a passenger in the `carries` axis below.
 *
 * PER ENTRY, so a `Frame` that batches a `Declare` and an `Interest` gives each
 * of them its own answer, and the same in both lists. The entry of the `Frame`
 * itself says `null`. No existing key moves, and the word is derived from the
 * message's bytes, so it does not change in an issued row.
 *
 * @values fields body
 *
 * AND WHAT THE END-TO-END JUDGE MADE OF A FRAME, at field-document revision 34.
 *
 * A payload that carries an end-to-end protection header -- a length, an
 * identifier, a CRC, a counter, in a layout YOU describe -- is read and judged
 * when a rule binds its key to a profile you registered (the declaration
 * spelling is under wz_dissect_pcap_fields_with_payloads below). The verdict
 * is one more key on the entry of the `Push` that carried it:
 *
 *     `e2e`  an object, ABSENT on every entry no profile rule covers
 *
 *     "e2e":{"profile":"demo-a","matched_rule":{"index":0,"pattern":"..."},
 *            "body_schema":"pkg.Pose",
 *            "opened":true,"payload_offset":16,"payload_bytes":4,
 *            "header":[{"name":"crc","offset":0,"bytes":4,"raw":N,"value":N},
 *                      {"name":"ident","offset":8,"bytes":4,"raw":N,"value":N,
 *                       "parts":[{"name":"domain","value":3}, ...]}, ...],
 *            "crc_computed":N,"crc_error":false,
 *            "length_field":20,"length_expected":20,
 *            "length_matches_frame":true,
 *            "counter":7,
 *            "counter_error":false,"timeout_error":false,
 *            "counter_reason":"none","silence_ms":12,
 *            "slot":{"keyexpr":"demo/a","zid":"...",
 *                    "identity":[{"name":"ident","value":N}]}}
 *
 * It is on the ENTRY, for the reason `payload` is: a `Frame` batches several
 * messages and a counter is a fact about one. A message that arrived as
 * fragments is judged where its chain completed, and its block is on the
 * entry under `above_transport.carried`. Only a `Push` carrying a `put` is a
 * frame; a key a rule covers whose payload is not a frame says why:
 * `"opened":false` and a `why`, and the keys that need a frame are absent.
 *
 * `crc_error`, `counter_error` and `timeout_error` are the three booleans of
 * the protocol's receiver. A frame whose CRC does not match is NOT judged for
 * its counter and moves no state. `counter_reason` is `none`, `repeat` (the
 * counter did not move) or `out_of_range` (it moved past the profile's
 * allowed gap), for analysis; `silence_ms` is the silence the timeout was
 * judged against. THE THREE LENGTH KEYS ARE INFORMATION AND NOT PART OF THE
 * CRC VERDICT: the CRC is taken over the length field as it stands on the
 * wire, so a sender that counts the length by another rule than the profile's
 * shows as `length_matches_frame: false` beside a clean CRC, and damage shows
 * as `crc_error: true`.
 *
 * THE COUNTER IS JUDGED PER SLOT. A slot is the key expression the frame was
 * published under, the sender, and the values of the profile's `slot.message`
 * fields (none by default); `slot` names it. The sender is the zid the
 * capture saw announced on the link, never a field of the header. Two senders
 * of one key do not share a counter unless the profile says `by_zid: false`.
 *
 * `null` MEANS NOT JUDGED, and `false` means judged and fine. When the
 * profile separates senders and the capture never saw this sender's
 * handshake, `slot.zid` is `null` and `counter_error`, `counter_reason` and
 * `timeout_error` are `null`: the CRC needs no state and is judged, the
 * counter would have to share a slot with every other unnamed sender and is
 * not. `timeout_error` and `silence_ms` are also `null` for a frame whose
 * packet carried no timestamp; `silence_ms` is `null` for the first frame a
 * slot received. `zid` is absent when the profile does not separate senders,
 * and `identity` when it names no message field. Frames are judged in the
 * order the document walks them, flow by flow and in capture order within a
 * flow, at the capture's own instants -- never the host's clock.
 *
 * STATE-DEPENDENT, so every cell under `e2e` is among the cells an issued row
 * may read differently later (see the list below): a front trim makes a slot's
 * oldest retained frame its first reception, and a zid learned late turns a
 * `null` verdict into one. A since-door (wz_dissect_live_fields_since) still
 * judges the rows its cursor passes over, so the first row it writes is judged
 * against the frames before it and not as a first reception.
 *
 * @values fields counter_reason
 *
 * AND WHEN A RECORD WAS CAPTURED, AND IN WHAT ORDER ROWS COME, at
 * field-document revision 31, selection-document revision 3, census revision 17
 * and retention revision 3.
 *
 * A RECORD'S TIME is the capture time of the packet that carried its FIRST BYTE:
 * the byte its row's `first_byte` names (on a byte stream, `message_at`). It is
 * not when the record was completed and not when this library got round to
 * decoding it. A record that spans two packets reports the first packet's
 * instant; a record decoded from bytes that waited behind a hole in a TCP stream
 * (until the hole filled, or was stepped over, or the capture ended) reports the
 * instant it was captured at, and not the instant the capture ended, which is
 * what every such record reported until revision 31. Two messages of one batch
 * differ only when the batch crosses a packet boundary between them. A record
 * whose bytes were decompressed out of an lz4 batch has no byte of its own on
 * the wire and takes its batch's instant. A datagram is one packet. A record
 * that begins in the bytes a hole took is never produced: the hole is announced
 * to the reader, which drops what it holds on the near side and scans for a
 * boundary, so no record's first byte is ever in a hole.
 *
 * THE CLOCK KEEPS THE NANOSECOND. What a push gave is what comes back, to the
 * digit: a classic pcap's microsecond fraction is carried (its nanosecond digits
 * are zero because the file never had them), a pcapng's `if_tsresol` is applied
 * exactly, and wz_dissect_live_push takes nanoseconds and keeps them. Every
 * figure that was in milliseconds is that divided by one million, rounded down,
 * so the two readings of one instant never differ: a `time` or `elapsed` term
 * and every `*_ms` key are milliseconds and keep their values; `ts_ns`,
 * `last_seen_ts_ns` and `oldest_ts_ns` are nanoseconds and now carry the digits
 * they used to drop (they ended in six zeros). `halves[].last_seen_ts_ns` is the
 * instant of the LATEST record the direction produced, so a record captured out
 * of order does not make a direction look to have gone quiet.
 *
 * THE ORDER OF ROWS, for a stream flow, is CAPTURE order: ascending by the
 * packet that holds the row's first byte (`first_byte.packet`), then by the
 * row's place in that packet. It was the order the session decoded the messages
 * in, which is the order their last bytes arrived in; the two parted whenever a
 * message completed after one that began later, as a unit spanning packets does
 * after a unit of the other direction that sat wholly inside one of them. The key
 * is total -- no two rows of a flow share a packet and a place -- so the order is
 * deterministic and does not depend on how many calls the rows arrived in. A row
 * whose first byte no packet can be named for takes the packet of the row before
 * it that had one, which keeps it beside its neighbours. A datagram flow's rows
 * were always in capture order, a flow's scouting rows follow its transport
 * rows, and flows are listed stream flows first, then datagram flows; the
 * packet is global to the capture, so rows of different flows merge on it. The
 * selection document's rows are the field document's, in the same order, and a
 * `max_messages_shown_per_flow` ceiling keeps the first rows of this order. `seq`
 * is NOT in this order: it is the order the handle first issued a row in, and
 * promises no position.
 *
 * AND WHICH TABLE A KEY EXPRESSION'S ID INDEXES, at field-document revision 30.
 *
 * A key expression on the wire is `(id, suffix)`, and the id means nothing
 * until you know whose table it indexes. zenoh puts that choice in ONE BIT of
 * the header of the message that carries the key: M set names the ids the
 * SENDER declared, M clear the ids the RECEIVER declared. The field tree
 * records it under a `keyexpr` node:
 *
 *     `mapping`   `1` when the M bit is set (the sender's table), `0` when it
 *                 is clear (the receiver's)
 *
 * It is the bit as written -- not a name, and not inverted -- and the `m` flag
 * on the same header is that bit read as a flag. It is present on Push,
 * Request, Response and the subscriber, queryable and token declarations,
 * whose headers have the bit, and on the `wire_expr` extension of an
 * undeclaration, which carries it in its own flags byte.
 *
 * ⚠ A DeclareKeyExpr HAS NO M BIT. Bit 6 of its header is reserved, so its
 * `keyexpr` node holds `id`, `suffix_len` and `suffix` and NO `mapping`: the
 * wire does not say which table the scope of a declared key expression
 * indexes, and the two upstream implementations answer it differently (zenoh
 * reads it as the receiver's, zenoh-pico as the sender's), so any value there
 * would be a decoder's choice reported as a measurement. Until revision 30 the
 * tree carried `mapping: 1` on it, beside `m: false`. The `m` flag stays on a
 * DeclareKeyExpr as the raw value of the reserved bit, which a conforming
 * sender leaves clear and which means nothing.
 *
 * The `keyexpr` a `carried` entry reports for a DeclareKeyExpr is the key it
 * declares, with a non-zero scope resolved out of WHICHEVER table knows that
 * id -- the sender's or the receiver's -- and `null` when neither does, or
 * when both do under different literals. That is the rule that binds the id
 * the declaration mints, so the row and every later reference to the id
 * agree. Both upstream implementations declare with scope 0, where none of
 * this arises. Until revision 30 the row read the scope in the declarer's
 * table only: `null` for a scope that only the other side held, and a literal
 * for one that both held differently.
 *
 * ⚠ ONE KEY EXPRESSION IS NOT YET HELD TO THIS: the restricted key of an
 * Interest. Its options byte has an M bit like the messages above, but its
 * `mapping` reads `1` whatever that bit holds, so do not take the value there
 * as the wire's.
 *
 * WHICH HALF IS `a`. Wherever a document or a record says `direction` -- a
 * row's, a record's, a `halves` entry's, a conduit's, a selector's `dir` -- the
 * two words are the two halves of a flow and nothing more:
 *
 *     `a`  the half that travels from `flow.low` to `flow.high`
 *     `b`  the half that travels from `flow.high` to `flow.low`
 *
 * `low` is the lesser of the flow's two endpoints, comparing the address bytes
 * as the capture stores them (a vsock context id is stored little-endian, so
 * its lowest byte decides first) and then the port, so the pair is the same
 * whichever packet was read first and a half keeps its word for the whole of
 * its flow. THE WORD IS A FACT ABOUT THE ENDPOINTS AND NOT ABOUT WHO OPENED THE
 * CONNECTION. A router on port 7447 and a client on a high port of the same
 * host give `a` to the ROUTER's half; a client bound below the router's port,
 * or sitting on a lower address, gives it to the client's. This header used to
 * call it
 * "conventionally the initiator", which is true of one arrangement of ports
 * and false of its mirror: nothing in the library ever assigned it by role.
 *
 * To learn who played which role, read the handshake: an `Init` whose `a`
 * flag is clear is the initiator's InitSyn and one whose flag is set is the
 * acceptor's InitAck, so the half that sent each is the half that played that
 * role. The rule above holds for the `tcp`, `udp`, `raweth` and `vsock` flows
 * these documents render (a serial line is rendered by none of them).
 *
 * ⚠ AN EMPTY `carried` IS A STATEMENT. A transport MID this build does not name
 * walks as the `Unknown` group -- the row says so under `name` -- and gets no
 * entry here, because `Unknown` is not a message and putting it in this
 * vocabulary would make the set something other than what the wire constants
 * define. The two facts are held to be the same set over all thirty-two values
 * a MID can take, by `the_message_vocabulary_is_the_one_the_dispatchers_produce`.
 *
 * @values fields message
 *
 * R2706 -- AND WHAT THE SESSION MADE OF THE FRAME, at field-document
 * revision 12.
 *
 * Every row now carries `above_transport`, whose `carried_state` is the
 * session's own verdict on that frame's payload. It exists because two facts
 * are unreachable by walking the row's bytes a second time, which is all this
 * document did before:
 *
 *   - `reassembled` -- the frame COMPLETED a fragment chain, and the records
 *     it carried are under `above_transport.carried` with an
 *     `above_transport.fields` tree beside them. Their bytes were never
 *     contiguous on the wire, so no second walk over this row could reach
 *     them, and until this revision a reader could not tell "this traffic
 *     carried nothing" from "five messages travelled and are not described".
 *   - `undecompressible` -- the session negotiated compression and could not
 *     open this body. The walk has no lz4 and halts at whatever record first
 *     fails, reporting a MID word indistinguishable from one this build's
 *     wire vintage does not know; this word is what separates them.
 *
 *     MOVED FROM A FRAME TO A BATCH. Compression wraps the whole
 *     batch behind a one-byte header, once each side has sent its Open; it
 *     never wraps one Frame's payload, which is where this reader used to look.
 *     A batch whose header says lz4 is now opened before any message is read
 *     -- this library is built with lz4 -- and its messages arrive as ordinary
 *     rows whose `first_byte` is `null` (no packet byte holds a decompressed
 *     message). `undecompressible` is left for a batch that does not open: ONE
 *     row stands for it, since no message inside it can be located, and its
 *     own walk is declined. A clear header is stepped over and the batch read
 *     as the wire carried it.
 *
 * The other four (`batch`, `nothing`, `fragment`,
 * `fragment_without_resolution`) arrive alone in their object, which is what
 * makes the key a DISCRIMINANT. A scouting row has no session frame and
 * carries `"above_transport":null`.
 *
 * ⚠ THE SPANS UNDER `reassembled` ARE NOT CAPTURE OFFSETS. They index the
 * buffer the chain was joined in, which exists only inside the reader, and the
 * row's own `offset_space` is untouched -- it still says where the FRAGMENT
 * stands, which stays measured. Do not add the two.
 *
 * Since field-document revision 22 each entry of `above_transport.carried`
 * also carries the `payload_decode` a row's own message carries, under the
 * same rule: present whenever a format was declared, in whichever state the
 * decode lands, and absent for a reader who declared nothing unless the
 * record's payload never crossed the wire (an SHM descriptor). It is decided
 * per RECORD, from that record's own subtree, so a chain that joined two
 * messages decodes each under its own key. A row's OWN `payload_decode` names
 * the first message of that row that has both a key and a payload, so on a row
 * carrying several it does not speak for the rest; the entries here are
 * per record. The spans inside a decoded payload index the joined buffer, in
 * the space of the entry's `start` and `end`, and are not capture offsets
 * either. Like the entry's `keyexpr`, the block starts from the resolved key,
 * so a live handle may write it differently once a declaration is decoded
 * late; see the list of cells a later document may rewrite. The document's own
 * `payload_mapping` and `payload_refusals` are fed by the decodes it performs,
 * so from revision 22 they count these records too: a capture whose only
 * refused samples were reassembled used to write both arrays empty.
 *
 * AND A FRAGMENT CHAIN READ WITH NO RING, at field-document revision 32 and
 * census revision 18. A flow whose capture holds no InitAck (`context.sn_mask`
 * is `null`, ordinarily because the capture began after the handshake) does not
 * know the size of the sequence-number ring. The ring decides one thing about a
 * chain: whether the step from one fragment to the next is consecutive across a
 * wrap. A step of plain `+1` is consecutive on every ring, so the chains of such
 * a flow are FOLLOWED. Until revision 32 they were not: every Fragment of the
 * flow read `fragment_without_resolution`, its `chain` was `null` and nothing was
 * reassembled. The rules are these.
 *
 *   - A continuation is accepted when its sequence number is exactly the
 *     previous fragment's plus one, as plain integers. A fragment of a chain
 *     that proceeds reads `carried_state: fragment` and a `chain.outcome` of
 *     `begun` or `continued`; the fragment that closes it reads `reassembled`,
 *     and its `above_transport.fields` and `above_transport.carried` are those of
 *     any reassembled message, as on a flow with a ring.
 *   - A step that is not `+1` is one only the ring could judge: a wrap, a gap
 *     or a repeat. The chain ENDS. The fragment that showed the step reads
 *     `carried_state: fragment_without_resolution`, because it could not be
 *     placed, and its `chain` is `{"outcome":"aborted","reason":"unresolvable",
 *     "chain_id":N}` with the identity of the chain it ended. `unresolvable` is
 *     never `out_of_order`: that word is the verdict on a ring the reader
 *     knows, and a flow carries one or the other. The chain's earlier fragments
 *     keep what they read when they arrived, and the fragments after the
 *     ending START FRESH, by the rule below.
 *   - WHAT A CHAIN'S START IS. The chain boundary markers (the `first` and
 *     `drop` extensions) are enforced only when the negotiated patch level says
 *     so, and a flow with no Init has no patch level: they are not enforced.
 *     A fragment that finds no chain open for its (direction, reliability,
 *     priority) then begins one, whatever it carries. So a capture that joined in
 *     the middle of a chain begins a chain at the first fragment it holds, and
 *     the message its close delivers does not begin at a message; the rest of a
 *     chain that ended `unresolvable` is the same. Such a close reads
 *     `reassembled` and its tree is whatever those bytes parse as, which is
 *     usually a halted batch and no message. Where only the InitSyn was seen the
 *     patch level is known and the markers ARE enforced: a fragment with no
 *     `first` that finds no chain open is `refused` with `missing_start_marker`,
 *     and the ring is still unknown.
 *   - `sn.verdict` is UNCHANGED and stays `without_resolution`. Following a
 *     chain says a continuation was the next integer; it does not say the frame
 *     arrived in order relative to a ring this reader never saw, and no verdict
 *     is claimed.
 *   - Where the ring IS known (an InitAck was seen) nothing here applies, and
 *     the rows read as they did at revision 30.
 *
 * The census follows the rows. For a flow with no InitAck, `unresolvable_fragments`
 * (in `exchanges.unread`, `payloads.gaps`, `keyexprs.gaps` and the throughput
 * gaps) counts the fragments that ended a chain this way, which are the rows
 * that read `fragment_without_resolution`, and no longer every fragment of the
 * flow. `fragment_chains` gains `aborted_unresolvable`, the same endings read as
 * chains, and its `begun`, `continued` and `completed` count the chains of such a
 * flow, which they did not. The messages those chains reassembled are in the
 * keyexpr totals (`puts` and the rest), the exchange plane and the payload plane,
 * and a selector's `kind == put` is `yes` on the rows that close them. The top
 * level `reassembly` group counts a chain of such a flow that was still open at
 * the end. A consumer pinned to an earlier revision that took
 * `fragment_without_resolution`, or a nonzero `unresolvable_fragments`, to mean
 * "this flow missed its handshake" must read `context.sn_mask` for that.
 *
 * AND WHICH END OF A DISCOVERY FLOW A NODE SENT FROM, at census revision 20. A
 * Scout or a Hello is one node speaking to a group or to whoever asked, so the
 * flow that carries one has no row in the node plane's `links`: that array
 * lists a flow only where both ends opened a handshake, and every row names
 * both. The node was under the right flow in `nodes[].flows` and no key said
 * which END of the flow it was. The node plane now carries a second array
 * beside `links`:
 *
 *     "ends":[{"node":2,"sender_end":"low","flow":{...}},
 *             {"node":3,"sender_end":"high","flow":{...}}]
 *
 *   - A row says: the node `nodes[node]` SENT a message that named it, from the
 *     `sender_end` of `flow`. `sender_end` is `low` or `high`, the two keys a
 *     flow object is indexed by, so `flow[sender_end]` is the endpoint it sent
 *     from. It is not called `end`: that key exists in this document as a
 *     number (see the ambiguity report), and one name must not carry both.
 *     Direction `a` is the half sent from the low endpoint (address first, then
 *     port), so the sender of an `a` message is `low` and the sender of a `b`
 *     message is `high`: the same halves the field document's `direction`
 *     names.
 *   - Three messages seat a sender. A Hello always does, because it always
 *     names its sender. A Scout does when it carries its optional zid; a Scout
 *     that leaves the zid out names no node and seats none. A multicast Join
 *     does. An Init does not: it is half of a handshake, its two ends are what
 *     `links` is for, and a flow that shows one Init and not the other has no
 *     row in either array.
 *   - THE RECEIVING END HAS NO ROW AND NO PLACEHOLDER. No message names it.
 *     Not the multicast group, which is not a node, and not the asker a Hello
 *     answers: the Hello went to that address, and nothing in it says a node
 *     lives there. A consumer asking who is at the other end gets no answer
 *     from this array, by design, and must not infer one from the flow's
 *     address.
 *   - A row is what was seen and not a verdict. Several nodes may be seated at
 *     one end of a flow (listeners share the scouting port), one node may be
 *     seated at both ends of one flow, and a flow whose two hosts each answer
 *     the other holds a row for each sender. There is one row per (node, end,
 *     flow), in the order they were first met: the Joins of the message lists
 *     first, then the datagram flows in their table order.
 *   - The array is always present, and is empty when no message named its
 *     sender. Every other key reads as it did at revision 19: `links`,
 *     `nodes[].flows` and the evidence counts do not change. The node plane is
 *     not narrowed by a selector, so every census door and the live handle
 *     carry the same array.
 *
 * @values census sender_end
 *
 * ⚠ AN INTEGER A JSON NUMBER WOULD MISREAD IS A STRING (field document 23, and
 * the same rule in the other documents below). A 64-bit integer that this
 * library reads off the wire or off a clock is written as a bare number while
 * every JSON reader holds it exactly, which is up to 2^53 - 1 (9007199254740991),
 * and as the same digits in a string beyond that. A reader on doubles (a
 * JavaScript `JSON.parse`, a `toDouble()`) loses the low bits above 2^53, and
 * one on `int64` falls back to its default above 2^63; both are silent, and a
 * wrong number is worse than a missing one. The line is 2^53 - 1 and not 2^63
 * because it has to be safe for the narrowest reader. A cell that can reach it
 * is therefore either a number or a string, and a consumer asks which before
 * it reads; a cell below the line is a number exactly as before.
 *
 * It applies to a `uint` (and a `bits`) field's `value` in every field tree;
 * to the `missing` of a row's `sn` and of the summary's `sequence` group; to
 * the `id` and `solicited_by` values the census and the summary write for a
 * declaration, an interest request and an unresolved alias; to the
 * `keyexpr_id` of a `carried` entry (a key that exists from field document 24
 * and takes the rule from its first appearance); to the `lease_ms` and
 * `last_seen_ts_ns` of a flow's `halves` (keys that exist from field document
 * 25 and take the rule from their first appearance: the lease is a wire
 * field's value and the instant is a clock's); to the `raw` and `value` of an
 * `e2e_wrap` or `e2e_open` field and the `value` of each of its `parts`, to
 * the `crc_computed` and `length_field` of an `e2e_wrap` or `e2e_open`
 * document and to the `length_expected` of an `e2e_open` document (those
 * documents take the rule from their first revision: a field of seven or eight
 * bytes can pass the line and one of six or fewer cannot, and the width is the
 * profile's, so a consumer knows from its own profile which cells to ask
 * about); to the `crc_computed`, `length_field`, `length_expected`, `counter`
 * and `silence_ms` of an `e2e` block and the `value` of each entry of its
 * `slot.identity` (keys that exist from field document 34 and take the rule
 * from their first appearance: the block's `header` fields are the cells the
 * stateless doors' fields are, and a CRC or a counter of eight bytes can pass
 * the line); to the `min_ns`, `max_ns`, `mean_ns` and `total_ns` of a census
 * latency object (keys that exist from census revision 17 and take the rule
 * from their first appearance: `total_ns` is a SUM, and 2^53 nanoseconds is 104
 * days of summed latency, which a long capture of many exchanges reaches); to
 * the `value`, `min`, `max`, `stored` and `ring_max` of a `transport_build`
 * layout row (that document takes the rule from its first revision: a sequence
 * number or a lease can be eight bytes, and the top of a nine-byte VLE is
 * 2^64 - 1); and to
 * `oldest_ts_ns` in the retention document. It does NOT apply to counts,
 * offsets, sizes and millisecond spans this library measures: those count
 * things the host holds, and stay bare numbers. Revisions: fields 23, census
 * 16, summary 5, retention 2, e2e_wrap 1, e2e_open 1, transport_build 1.
 * The gap total saturates at the top of `u64` instead of wrapping.
 *
 * @values fields carried_state
 *
 * AND THE SESSION'S PER-FRAME VERDICTS, at field-document
 * revision 14. Every key below is emitted on every row (or flow) it can occur
 * on, and is `null` where it does not apply -- never absent.
 *
 * Per ROW:
 *
 *   "sn":{"verdict":..,"missing":N|null,
 *         "conduit":{"direction":"a"|"b","priority":..,"reliable":bool}}
 *
 *     The sequence-number verdict, judged against the previous frame on the
 *     SAME conduit -- zenoh numbers each (priority, reliability) pair
 *     separately, per direction, so a lane keyed on anything less reads every
 *     interleave as a gap. `missing` is filled for `gap` only. `null` on every
 *     message that carries no SN (handshake, keepalive, close). A Fragment's
 *     priority is its `ext_qos` band like a Frame's; `priority` is the band's
 *     NAME, never its number.
 *
 *     `verdict` is one of `baseline` (first frame on the conduit),
 *     `continuous`, `gap`, `duplicate`, `out_of_window` (behind, or past the
 *     forward half-window -- a participant drops these, so they are not loss),
 *     or `without_resolution` (no InitAck seen, so the ring is unknown). That
 *     word stays on a Fragment whose chain IS followed without the ring (see
 *     the fragment chain paragraph above): following a chain is not a verdict.
 *     `priority` is one of `Control`, `RealTime`, `InteractiveHigh`,
 *     `InteractiveLow`, `DataHigh`, `Data`, `DataLow`, `Background`.
 *
 * @values fields verdict
 * @values fields priority
 *
 *   "chain":{"outcome":..,"reason":..|null,"chain_id":N|null}
 *
 *     What the reassembly router did with a Fragment row, and an identity
 *     shared by every row of one chain (unique within the flow, counted from 0
 *     in the order chains began). The identity names ROWS; it is NOT a
 *     coordinate into the joined buffer, whose offsets stay off this document.
 *     `reason` is filled for `aborted` and `refused`; `chain_id` is `null` for
 *     `refused`, which allocates no chain. `null` on every non-Fragment row.
 *     (Until field-document revision 32 it was also `null` on every Fragment of
 *     a flow read before any InitAck, where no router ran: the router runs on
 *     those now, and `carried_state: fragment_without_resolution` is the
 *     fragment that ended a chain as `unresolvable`.) `superseded` is declared
 *     and not emitted today: the router
 *     reports a restart as `begun` for the new chain, so the stranded chain
 *     ends WITHOUT a row.
 *
 *     `outcome` is one of `begun`, `continued`, `reassembled`, `aborted`,
 *     `refused`. `reason` is one of `out_of_order`, `capacity_overflow`,
 *     `sender_dropped`, `superseded`, `unresolvable` (with `aborted`) or
 *     `peer_quota`, `pool_exhausted`, `missing_start_marker` (with `refused`).
 *     `unresolvable` is the router's refusal to judge a step it has no ring for
 *     and `out_of_order` its verdict on a ring it knows; a flow carries one or
 *     the other.
 *
 * @values fields outcome
 * @values fields reason
 *
 *   "first_byte":{"packet":N,"payload_offset":N,"frame_offset":N|null}
 *   "l2":{"src":"aa:bb:cc:dd:ee:ff","dst":"..","frame_offset":0,"length":14}|null
 *
 *     The capture packet holding the row's first byte, where that byte sits
 *     in the packet's transport payload, and where it sits in the CAPTURED
 *     FRAME (link header included) -- so a packet view can highlight it
 *     without parsing a header. `frame_offset` is `null` where one packet's
 *     bytes cannot place it (a payload rebuilt from IP fragments, a vsock
 *     record). `first_byte` is `null` on a WebSocket flow: the row's
 *     coordinate names the ws frame header, and the message sits past it,
 *     masked. `l2` is the Ethernet II header of that packet, `null` on any
 *     other link.
 *
 *     Since field-document revision 21 `l2` also PLACES the header: its
 *     `frame_offset` (where it begins in the captured frame, the start) and
 *     its `length` (how many bytes it spans, fourteen), so a packet view that
 *     draws the header in the frame's bytes counts no link header of its own.
 *     `frame_offset` here means what it means on `first_byte`: an offset from
 *     the frame's first byte. The span is the header proper -- destination,
 *     source and the two-byte EtherType field -- and holds NO VLAN or QinQ tag.
 *     Each tag is four bytes that follow the span, the EtherType field then
 *     reads the tag's protocol id, and this object does not place the tags.
 *
 * Per FLOW, beside `flow`:
 *
 *   "context":{"phase":..,"negotiated":bool,"lowlatency":bool|null,
 *              "compression":bool|null,"qos":bool|null,"patch":N|null,
 *              "sn_mask":N|null,"batch_size":N|null,"version":N|null}
 *
 *     What the handshake this flow carried negotiated, as of its end. The
 *     three capabilities are `null` until BOTH Inits were seen, rather than
 *     the `true` a half-folded negotiation starts from. `sn_mask` is the ring
 *     every `sn.verdict` on the flow was judged at; `null` there is why they
 *     all say `without_resolution`. It can reach 2^63-1: read it as a 64-bit
 *     integer, not a double.
 *
 *     Since field-document revision 22 the flow also says its protocol
 *     `version`, which used to be readable only from the `Init` row's tree.
 *     It is the version of the InitAck when one was observed and of the
 *     InitSyn until then, and `null` when no Init was -- a different fact from
 *     a version of 0. The two agree on any session that comes up, because the
 *     acceptor refuses an InitSyn whose version is not its own and answers
 *     with its own; the choice decides only what a refused session, or one
 *     joined mid-handshake, reports. `context` is the flow's value at the END
 *     of the document and is not a row, so the promise about issued rows does
 *     not cover it.
 *
 *     `phase` is one of `unseen`, `half_init`, `init_complete`,
 *     `established`, `closed`.
 *
 *     Since field-document revision 26 -- WHAT `negotiated` MEANS, and what a
 *     flow that did not see its handshake says. `negotiated` is `true` once
 *     BOTH Inits of the handshake were observed, the InitSyn and the InitAck,
 *     one in each direction; it stays `true` through the `Open` exchange and
 *     through a `Close`, and it is `true` at `init_complete`, before any
 *     `Open`. The Init exchange is what fixes the session's parameters: the
 *     three capabilities, the patch level and the size parameters. The `Open`
 *     exchange carries none of them, so the Open adds nothing to a negotiation
 *     and its absence withholds nothing from one.
 *
 *     `negotiated` is `false` for a flow whose handshake was not observed: a
 *     capture that begins at or after the Open (a `Close` alone, Frames and
 *     Fragments then a `Close`), and a capture that saw one Init and then
 *     nothing or a `Close`. `phase` is no evidence of a negotiation: it says
 *     where the session IS, and `closed` is what a `Close` makes it from any
 *     state, so `"phase":"closed"` with `"negotiated":false` is the ordinary
 *     reading of a flow that began at its `Close`.
 *
 *     `lowlatency`, `compression` and `qos` are `null` whenever `negotiated`
 *     is `false`. When it is `true`, each is `true` only if BOTH sides offered
 *     it, and `false` otherwise: `null` is "not known", a different answer
 *     from `false`. `sn_mask` and `batch_size` are the InitAck's answer and
 *     are `null` until one was observed. `patch` and `version` are what the
 *     Inits seen announced: with one Init seen they are that Init's
 *     announcement and not yet the session's agreement, and `negotiated` says
 *     whether both were seen. A cell that does not follow from an observed
 *     message is `null`, never a default.
 *
 *     The values that moved at revision 26: a flow that began at its `Close`,
 *     or joined after the handshake and ended in one, or saw one Init and a
 *     `Close`, used to read `"negotiated":true` with the capabilities the
 *     fold starts from (`true`), and now reads `false` and `null`. A flow
 *     whose Init pair was seen reads as it always did. How messages are READ
 *     did not move at that revision: a flow joined mid-session decodes its
 *     Frames, and read its Fragments as `fragment_without_resolution`, exactly
 *     as before. The Fragments moved at revision 32 (see the fragment chain
 *     paragraph above).
 *
 *     Since field-document revision 29 -- WHAT `qos` MEANS. `qos` is `true`
 *     only if BOTH Inits offered QoS. An Init offers it in either of the two
 *     encodings Zenoh writes, the unit extension (id 1, no body) and the z64
 *     extension on the same id (header 0x21, the one an endpoint with priority
 *     or reliability metadata sends), in any combination of the two across the
 *     pair. A z64 extension offers QoS by its BODY and not by its header: a
 *     body of 0 is Zenoh's "no QoS", so an Init carrying one offers nothing,
 *     and neither does a chain Zenoh refuses (both encodings at once, or a body
 *     that is no state). The cell says what the Inits offered, not whether the
 *     exchange then succeeded: a band the acceptor's own configuration rules
 *     out ends the handshake before any `Open`, and `qos` still reads what the
 *     two Inits offered.
 *
 *     The values that moved at revision 29: a session whose Inits carried the
 *     z64 encoding read `"qos":false` beside `"negotiated":true`, and now
 *     reads `true`. A flow whose Inits both carry the unit encoding, one whose
 *     Inits carry neither, and one whose Init pair was not seen read as they
 *     always did.
 *
 * @values fields phase
 *
 * Also per FLOW, beside `context`, and since field-document revision 25 --
 * WHAT EACH DIRECTION'S SENDER HAS DONE:
 *
 *   "halves":[{"direction":"a","lease_ms":N|null,"last_seen_ts_ns":N|null,
 *              "close_seen":bool,"fin_seen":bool|null,"rst_seen":bool|null},
 *             {"direction":"b", ...the same six keys...}]
 *
 *     Two entries, `a` then `b`, with the `direction` the rows carry. The
 *     context says what the handshake settled for the SESSION; whether a
 *     sender has gone quiet, and how it stopped, are facts about each SENDER,
 *     so the unit here is the direction. `lease_ms` is the lease that
 *     direction's sender announced in its own `Open`, in milliseconds, and
 *     `null` until that `Open` was read; it is the figure that judges THIS
 *     direction going quiet. `last_seen_ts_ns` is the capture instant of the
 *     last message record the direction produced, decodable or not (the latest
 *     instant any of its records carried, from revision 31), in the unit
 *     and on the clock a drained record's `ts_ns` uses; `null` when nothing was
 *     read with a clock, a different fact from 0. `close_seen` is whether the
 *     direction carried a `Close`, whichever scope the Close asked for (the
 *     Close row says). `fin_seen` and `rst_seen` are whether a TCP FIN or RST
 *     was observed on the direction, and `null` on a flow that is not TCP,
 *     where the flag does not exist.
 *
 *     EVERY CELL IS AN OBSERVATION AND NONE IS A VERDICT. Whether a direction
 *     has expired is arithmetic the reader does on `lease_ms`,
 *     `last_seen_ts_ns` and its own clock; nothing here computes it. The two
 *     instants-and-leases follow the integer rule: a bare number up to
 *     2^53 - 1 and a string of the same digits above it, and
 *     `last_seen_ts_ns` is past that on a real clock. Like `context`, `halves`
 *     is the flow's value at the END of the document and is not a row.
 *
 * And at the TOP LEVEL, `"reassembly":{"expired_chains":N,
 * "abandoned_at_end":N,"abandoned_on_eviction":N}` -- the chains that ended
 * with NO row: past their deadline, still open when the capture stopped, or on
 * a flow the cap evicted. A `chain_id` with a `begun` row and no closing one is
 * one of these. The same group the command line's capture report carries.
 *
 * R2629 -- AND A SCOUTING DATAGRAM IS A ROW, at field-document revision 10.
 *
 * A datagram flow's `messages` now also holds its SCOUT and HELLO datagrams.
 * Until this revision they were not rendered at all: a discovery capture
 * reached this document as `"messages":[]` with no disagreement named, while
 * the summary beside it counted `"scouting":N`. If you read an empty listing
 * on a scouting flow from revision 9 or earlier as "nothing was said", that
 * reading was wrong.
 *
 * Such a row carries the keys every walked row carries. Its `carried` holds one
 * entry, `Scout` or `Hello`, read off the MID byte in the SCOUTING space -- and
 * that space reuses the transport space's numbers: `0x01` is `Scout` here and
 * `Init` on a session. So the WORD, never the byte, tells you which space a
 * row was read in, and no word belongs to both. `keyexpr` and `keyexpr_cause`
 * are `null` on it, because a scouting message references no key.
 *
 * ORDER: a flow lists its transport messages first and its scouting messages
 * after them, each row with its own `packet`. Merge on `packet` when you need
 * one timeline.
 *
 * R2180 — AND A DOCUMENT SAYS WHICH OF ITS TOP-LEVEL KEYS ARE PLANES, which is
 * a third question neither number above can answer. A PLANE is an independent
 * fold over the capture that this build may be unable to feed at all; when it
 * cannot, the key is emitted as
 *
 *     "exchanges":null
 *
 * rather than as an empty table, because `{"rows":[]}` would say the CAPTURE
 * held no queries when the truth is that this BUILD cannot see one. Read the
 * two apart: `null` means "no answer", an empty table means "the answer is
 * none".
 *
 * ⚠ THE TRAP THIS CLOSES, and a consumer had already fallen into it: `null`
 * carries no keys, so nothing inside an absent plane says it is one. Every
 * plane this build CAN feed carries `narrowed_by_selector`, and reading that as
 * "the mark of a plane" works right up to the build that cannot feed it. What
 * was left was the guess "a top-level null is an absent plane" — true of this
 * library, promised by nothing, and it would stop being true the day a
 * non-plane key went null.
 *
 * SO THE DOCUMENT CARRIES THE LIST. Its envelope reads
 *
 *     {"document":{"name":"census","revision":20,
 *                  "planes":["exchanges","interests","keyexprs","nodes",
 *                            "payloads"]}, ...}
 *
 * A key in that list is a plane: `null` means this build cannot feed it. A key
 * NOT in it is not a plane and is NEVER null. In the document rather than
 * behind a second door on purpose — what this door hands you is an owned
 * string you may store, forward or compare against one you took earlier, and a
 * plane list fetched separately could be paired with a document from another
 * build with nothing able to notice. Here the list and the revision travel
 * together.
 *
 * A document that declares no plane OMITS the key rather than carrying an empty
 * list, and that silence is safe to read for the same reason: no document may
 * emit a PLANE it has not declared, in either shape you would recognise one by
 * — a top-level `null`, or a top-level object carrying `narrowed_by_selector`
 * — so a document with no `planes` key can never hand you an ambiguous one.
 * `every_top_level_null_is_a_declared_plane` holds that over all six.
 *
 * R2181 widened this sentence and the arm behind it in the same change. It read
 * "may emit a top-level `null`", which is the narrower of the two shapes, so
 * the contract promised more than the gate checked.
 *
 * @planes census exchanges
 * @planes census interests
 * @planes census keyexprs
 * @planes census nodes
 * @planes census payloads
 *
 * `the_header_and_the_library_agree_about_every_plane` holds both directions,
 * so a plane added later cannot arrive unmarked and a marker cannot outlive the
 * plane it names.
 *
 * R2184 — AND WHICH KEYS ARRIVE BESIDE A VALUE, which is the third axis and the
 * one the two above are each blind to.
 *
 * The key set is a UNION over the whole document, so it cannot say "sometimes
 * absent": `value` is in the field document's key set whether the object that
 * would carry it opened or not. The vocabulary sees the WORD and stops there.
 * So the sentence you actually need -- IF `kind` IS `opaque`, DO NOT LOOK FOR
 * `value` -- was expressible in neither, and every consumer of this ABI was
 * reading it off whatever the rendering happened to do. One of them lost
 * `opaque` to exactly that.
 *
 * Every family in `value_families` now carries a `carries` axis:
 *
 *     {"name":"fields","revision":34,"key":"kind","values":[...],
 *      "carries":[{"word":"bits","shapes":[["end","name","start","value"]]},
 *                 {"word":"opaque","shapes":[["end","name","start"]]}, ...]}
 *
 *     {"name":"census","revision":20,"key":"mode","values":[...],
 *      "carries":null}
 *
 * `null` is a VALUE here and not an absence: it says the word is a PASSENGER --
 * it decides nothing about the object it sits in, which is a record whose shape
 * something else fixes, and where an inapplicable companion arrives as `null`
 * rather than as a missing key. A list says the word is a DISCRIMINANT, and
 * gives every SHAPE that word's object is emitted in.
 *
 * ⚠ A LIST OF SHAPES AND NOT ONE SHAPE, because a word does not always fix the
 * whole object. `fields[].offset_space == "stream_byte"` arrives in two shapes,
 * with `payload_decode` and without, because that plane is present only when
 * you supplied a format map -- so the word decides `message_at` and does not
 * decide `payload_decode`, and both are true at once. A key in EVERY shape of a
 * word is one you may read unconditionally; a key in some of them is one to
 * test for.
 *
 * @carries census asker passenger
 * @carries census cause passenger
 * @carries census declarer passenger
 * @carries census family passenger
 * @carries census kind passenger
 * @carries census link passenger
 * @carries census mode passenger
 * @carries census offset_space passenger
 * @carries census sender_end passenger
 * @carries fields body passenger
 * @carries fields carried_state discriminant
 * @carries fields counter_reason passenger
 * @carries fields direction passenger
 * @carries fields family passenger
 * @carries fields keyexpr_cause passenger
 * @carries fields kind discriminant
 * @carries fields link passenger
 * @carries fields message passenger
 * @carries fields offset_space discriminant
 * @carries fields outcome passenger
 * @carries fields phase passenger
 * @carries fields priority passenger
 * @carries fields reason passenger
 * @carries fields selected passenger
 * @carries fields state discriminant
 * @carries fields under passenger
 * @carries fields verdict passenger
 * @carries fields wrong passenger
 *
 * `the_header_and_the_library_agree_about_every_carries_axis` holds both
 * directions, so a family reclassified later cannot arrive unmarked and a
 * marker cannot outlive the family it names.
 *
 * ⚠ THE CENSUS'S FIVE ARE PASSENGERS BECAUSE ITS ROW EMITTERS ARE
 * STRAIGHT-LINE, not because nobody looked: every row writes every key and puts
 * `null` where a value does not apply. That is a measured property of this
 * build, held by `the_declared_carries_axis_is_the_one_the_emitters_render`
 * over rendered documents, and a row emitter that started choosing keys by a
 * word fails there rather than reaching you.
 *
 * R2119 — THE FIRST RENAME TO USE THAT NOTICE, so the paragraph above is now
 * a description of something that happened rather than a promise. At census
 * REVISION 2 the node rows carried two keys for one value:
 *
 *     "offset_space":"stream_byte","first_anchor":43,"first_packet":43
 *
 * `first_packet` was the old name and it was WRONG on a stream link, where
 * the value is a byte offset — `offset_space` beside it has said so since the
 * revision before. `first_anchor` is the name, and it is the one the
 * throughput rows already used.
 *
 * R2123 — AND REVISION 3 DROPPED IT, which is the whole dance run once end to
 * end: announced where a consumer could see it, then removed a revision later.
 * A program written against revision 1 or 2 that reads `first_packet` gets
 * nothing from revision 3, which is what the notice was for. Read
 * `first_anchor`.
 *
 * Revision 3 also ADDS `anchor_intervals` to each throughput row — one extent
 * per coordinate space that contributed, with the record count in each. A row
 * folds every flow and both directions, so `anchors_exact:false` says the
 * pair covers only part of it; the intervals say which parts there are and
 * how much of the row each holds.
 *
 * R2456 — REVISION 10 GIVES THE NODE ROWS THE SAME PAIR, and this one is worth
 * a paragraph because of what it lets you ask:
 *
 *     "offset_space":"packet","first_anchor":4,"last_anchor":9,
 *     "anchors_exact":true
 *
 * `last_anchor` is the anchor of the LAST message that named this node. The
 * node plane is CUMULATIVE — a node that goes away is never removed from it —
 * so with a first anchor alone "this node is gone" could not be asked of this
 * document at all, and comparing two censuses could not answer it either: the
 * earlier node set is always a subset of the later one. A node whose
 * `last_anchor` stops moving while the census around it goes on growing is one
 * that stopped appearing. How long a silence means something is YOUR
 * threshold, but it is now measured against a coordinate this library gave
 * you rather than one you had to invent.
 *
 * `anchors_exact` is the same warning it is on a throughput row, reached the
 * same way: a node is named on many flows, an anchor is a coordinate in ONE
 * space, and a node seen both on a UDP flow and inside a TCP stream has two
 * numbers that cannot bound one interval. `false` means the pair covers only
 * the observations in the space `offset_space` names — so treat the pair as an
 * interval only when this is `true`.
 *
 * ⚠ Revision 10 also CHANGES A VALUE without moving its key. `offset_space` on
 * a node first named by a HELLO used to report whichever space the reader's
 * last message list was in; it now reports `"packet"`, which is what a
 * scouting datagram's anchor has always been. A consumer that stored node
 * anchors from revision 9 or earlier and compared them across a discovery-only
 * node was comparing coordinates it could not have known were mislabelled.
 *
 * R2457 — REVISION 11: A KEYEXPR ID SPACE IS KEYED BY SESSION, AND AN
 * UNRESOLVED REFERENCE SAYS WHY.
 *
 * A zenoh session may hold more than one link (`transport/unicast/max_links`).
 * Until this revision the observer keyed each id space by the FLOW, so a
 * `DeclKexpr` sent on the link that was dialled first and a record referencing
 * that alias sent on the second landed in different tables and NEITHER
 * resolved. It never cross-resolved — the error was always in the safe
 * direction — but on a two-link session every reference published after the
 * second link came up was reported unresolved.
 *
 * The unit is now the session, grouped by the zid pair the handshake named.
 * That pair IS the session rather than an approximation: zenoh keys its
 * established unicast transports by zid, so a second link with a zid it
 * already holds joins that transport instead of making a new one. Two DIFFERENT
 * sessions still get separate spaces, so their colliding ids stay unrelated.
 *
 * ⚠ SO VALUES MOVE UNDER STATIONARY KEYS, and on a multilink capture they move
 * a lot: rows appear in `keyexprs.rows[]` that revision 10 reported as
 * unresolved, and `unresolved_records` falls. If you stored counts from an
 * earlier revision, they are not comparable across this boundary.
 *
 * Each `keyexprs.unresolved[]` row now carries `cause`:
 *
 *     {"space":"a","id":7,"references":41,"cause":"no_session"}
 *
 * `no_declaration` — the session was named and nothing on it declared the id.
 * The gap is real: look for a lost batch, or a capture that began after the
 * declaration.
 *
 * `no_session` — the flow this reference travelled on never showed a two-sided
 * handshake, so the observer could not attribute it to a session at all. It
 * still resolves that flow's OWN declarations, exactly as before, but a
 * sibling link of the same session is a space it cannot join. This is what a
 * capture started mid-session looks like, and it is the arm that says "start
 * capturing earlier", not "hunt for a missing declaration".
 *
 * Folded into one `unresolved` count — which is all revision 10 could give
 * you — those two are indistinguishable, and the consumer report that asked
 * for this had derived exactly that: the acceptance is not that multilink
 * resolves, it is that what STILL does not resolve says which of the two it is.
 *
 * wz_dissect_transport_message is the one door with no such revision, and
 * deliberately: its document is a FIELD TREE whose keys are the walkers' own
 * names, generated per protocol element, so there is no fixed key set for a
 * revision to be about. wz_dissect_transport_message_in returns the same tree
 * and has none for the same reason.
 *
 * The live door emits no document at all, so it is outside this scheme
 * rather than an omission from it. A field read by OFFSET cannot be read by
 * name and cannot tolerate an unknown one, so ONCE A LAYOUT HAS SHIPPED, a
 * layout change is a new struct and a new door, never a quiet
 * reinterpretation of the old one. That rule stands.
 *
 * R2108 (ABI 12) USED AN EXCEPTION TO IT, ONCE, AND THIS PARAGRAPH IS THE
 * RECORD OF WHY — because an exception nobody wrote down is read by the next
 * person as a precedent, and this one is not.
 *
 * The struct was called wz_dissect_record_v1 for one day. R2108 renamed it to
 * wz_dissect_record and widened it in place rather than adding a _v2 beside
 * it. The conditions that permitted that, all measured on 2026-08-25 rather
 * than assumed:
 *
 *   - this repository has ZERO tags and ZERO releases, and its latest-release
 *     endpoint answers 404, so no layout here has ever been published as a
 *     release artifact;
 *   - wz_dissect_record_v1 reached origin at 15:46 that same day;
 *   - the only known downstream consumer's own report predates that push and
 *     says its integration begins by moving its pin AFTER a push, so it had
 *     not taken the struct.
 *
 * NONE OF THAT WILL BE TRUE OF THE NEXT LAYOUT CHANGE. If any of those three
 * has stopped holding when you read this, the rule above applies unmodified:
 * add a new struct and a new door.
 *
 * WHAT ACTUALLY CARRIES COMPATIBILITY IS THE NUMBER, not a suffix on a name.
 * wz_dissect_abi_version() is the instrument: a consumer pinned to 11 meets 12
 * and parts company there, which is the whole mechanism. A version suffix on
 * the type was a SECOND marker for the same fact, and two markers for one fact
 * are two things that can disagree — which is why the suffix is gone rather
 * than incremented.
 *
 * R2173 — THREE KINDS OF NOT-KNOWING, AND THEY ARE DIFFERENT ANSWERS.
 *
 * The KIND family below has said for a while that WZ_DISSECT_KIND_UNDECODABLE
 * (this reader failed) and WZ_DISSECT_KIND_UNKNOWN (a MID this build does not
 * recognise) are both answers and neither is the absence of one. There is a
 * THIRD, it belongs to every family here, and until this paragraph it was
 * nowhere:
 *
 *   1. THIS READER FAILED — a value the library reports because it could not
 *      decode. `WZ_DISSECT_KIND_UNDECODABLE`. About wz.
 *   2. THE WIRE CARRIED SOMETHING THIS BUILD DOES NOT KNOW — a value the
 *      library reports because the traffic was strange.
 *      `WZ_DISSECT_KIND_UNKNOWN`. About the network.
 *   3. YOUR SWITCH FELL THROUGH TO ITS DEFAULT — the library reported a value
 *      THIS HEADER does not list, because the library is NEWER than the header
 *      you compiled against. About the two of us, and about nothing else.
 *
 * ⚠ THE THIRD MUST NOT BE FOLDED INTO THE SECOND. Reporting "the wire sent
 * something strange" about an ordinary message whose only fault is being newer
 * than your header is a confident wrong answer, and a confident wrong answer
 * is worse here than silence.
 *
 * WHICH OF THESE APPLIES IS PER FAMILY, and each family says so in its own
 * comment block, in a form a gate reads:
 *
 *     @unknown <FAMILY> <policy>
 *
 * with `policy` one of `newer-build`, `ignore-bits`, `caller-supplied` or
 * `not-an-enumeration`; and, where a family ALSO reports not-knowing as a
 * VALUE (only KIND does today),
 *
 *     @unknown-sentinel <FAMILY> <MEMBER>
 *
 * `scripts/lib/capi_unknown_value_policy.py` holds every family to a marker
 * and every marker to its consequence -- contiguity, powers of two, a named
 * refusal code -- so a family added later cannot arrive unclassified.
 *
 * @unknown H not-an-enumeration
 */
#ifndef WZ_DISSECT_H
#define WZ_DISSECT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Success. One value, and there is no second one to come: a door either did
 * what it was asked or returns one of the negative codes below.
 *
 * @unknown OK not-an-enumeration */
#define WZ_DISSECT_OK 0

/* R2173 — THE ERROR CODES, and what a code you do not recognise means.
 *
 * They are contiguous downward from -1 for the same reason the KIND numbers
 * are contiguous upward: a code added later takes the next one, so a consumer
 * that does not know it lands on its own default rather than on a neighbour's
 * case. A code this header does not list means the LIBRARY IS NEWER THAN THIS
 * HEADER -- it does NOT mean the call did something exotic. Treat it exactly
 * as you would treat a failure you do know: non-zero is a failure, and the
 * specific codes are for telling one failure from another.
 *
 * @unknown ERR newer-build */
#define WZ_DISSECT_ERR_INVALID_ARG (-1)
#define WZ_DISSECT_ERR_BAD_CAPTURE (-2)
#define WZ_DISSECT_ERR_DECODE (-3)
/* R311y854 -- the selector did not compile. Its own code and not
 * INVALID_ARG, because the two are answered by different people: an invalid
 * argument is the caller's bug, a selector is text an operator typed. */
#define WZ_DISSECT_ERR_SELECTOR (-4)
/* R311y856 -- a payload declaration did not install. Its own code for the
 * reason SELECTOR is not INVALID_ARG: a selector and a format declaration
 * are two different texts a person writes, and a UI that could not tell
 * which box to send them back to would be answering neither. Call
 * wz_dissect_declarations_diagnose to learn which line and why. */
#define WZ_DISSECT_ERR_DECLARATION (-5)
/* R2205 -- the message's bytes are GONE from this reader. A retention ceiling
 * trimmed them, the list was evicted, or the record names a message this
 * handle no longer holds. POSITIONAL: a NEWER message of the same list still
 * answers, so grey this one out and carry on. */
#define WZ_DISSECT_ERR_BYTES_RETIRED (-6)
/* R2205 -- this message's list NEVER hands back bytes, and the difference from
 * the code above is the one a caller acts on: retry versus never. Two lists
 * are in it, each for a stated reason -- one anchors to a PACKET index, so you
 * are already holding the bytes (`anchor` is your own push ordinal and
 * `unit_offset` the place inside it), and one was recovered from an encrypted
 * transport, walked while the plaintext was alive and never retained. */
#define WZ_DISSECT_ERR_NO_BYTE_SOURCE (-7)
/* R2373 -- a container handed to wz_dissect_live_follow came back SHORTER than
 * what the handle has already read from it. Its own code and not BAD_CAPTURE,
 * because the bytes are not the problem: a container only a writer appends to
 * cannot shrink, so this says you handed over a DIFFERENT buffer -- a reopened
 * file, a truncated one, a length taken from the wrong place. Folded into the
 * capture error it would send you to inspect a capture that is fine. */
#define WZ_DISSECT_ERR_CONTAINER_SHRANK (-8)
/* This RECORD did not complete a fragment chain, so
 * wz_dissect_live_reassembled_bytes has no joined buffer for it. Per record,
 * unlike NO_BYTE_SOURCE, which refuses a whole list: another record of the
 * same list may answer. Unlike BYTES_RETIRED, asking again never will. */
#define WZ_DISSECT_ERR_NOT_REASSEMBLED (-9)
/* The container bytes handed to wz_dissect_pcap_frame_bytes hold NO
 * packet with that number. Its own code and not BAD_CAPTURE, because nothing is
 * wrong with the container: it reads as far as it goes, and the number is not
 * among the packets it holds -- one past the last, a prefix cut inside the
 * record that would hold it, or a prefix shorter than the one the number was
 * issued against. A bad capture sends you to the file; this sends you to the
 * length you passed. A LONGER prefix of a growing capture may hold the packet,
 * which is what separates it from BYTES_RETIRED's "gone from this reader". */
#define WZ_DISSECT_ERR_NO_SUCH_PACKET (-10)

/* R311y887 -- LIMIT PRESETS, for the doors that take one as an argument.
 *
 * An int and not a struct: a struct across this boundary would freeze wz's
 * DissectionLimits layout into the ABI, so the next axis it bounds would be a
 * break rather than an edit. An int grows by gaining VALUES, and a consumer
 * that does not know a new one simply never passes it.
 *
 * NONE is zero so a zero-initialised argument reads a file the way every door
 * here read one before presets existed. An UNKNOWN value is
 * WZ_DISSECT_ERR_INVALID_ARG and never a quiet fall back to unbounded -- a
 * caller that believes it asked for a ceiling must not be given none.
 *
 * R2173 — so this family's not-knowing runs the OTHER WAY from every other one
 * here. You PASS these; the library does not report them. A preset this build
 * does not know is refused with WZ_DISSECT_ERR_INVALID_ARG, and a preset YOU
 * do not know is simply one you never pass. There is nothing for a `default`
 * to mean.
 *
 * @unknown LIMITS caller-supplied */
#define WZ_DISSECT_LIMITS_NONE 0
#define WZ_DISSECT_LIMITS_LIVE_TAP 1

/* R2775 (open debt 804) -- THE REVISION AS A MACRO, beside the function that
 * reports it. wz_capi_c.h has carried this pair since R2301; this header did
 * not, so a consumer of these doors had one shape available and it was the
 * wrong one.
 *
 * HOW TO USE THE PAIR. The macro is what you COMPILED against; the function is
 * what you are RUNNING against. They differ only when a build is linked to a
 * library it was not compiled for -- a prebuilt library handed in from
 * elsewhere, with this header taken from a different checkout -- which is the
 * one failure a header cannot detect on its own:
 *
 *     if (wz_dissect_abi_version() != WZ_DISSECT_ABI_REVISION) { ... }
 *
 * Without the macro a consumer can only keep its OWN copy of the number. That
 * copy answers "is this the revision I adopted" and never "is this the library
 * my header describes", and it goes stale with no signal when the library
 * moves. A consumer reported exactly that: its hand-held constant was the only
 * shape this header allowed, and a stale literal was the failure twice in one
 * day -- once in that consumer's tree, once in this crate's own C test.
 *
 * Adding the macro does NOT move the revision. A define is compiled in, not
 * linked, and the revision moves for a SYMBOL or for the memory rule. It moves
 * WITH the function and never on its own: capi_abi_pin.py reads this define,
 * calls the function, and refuses when the two disagree.
 *
 * @unknown ABI not-an-enumeration */
#define WZ_DISSECT_ABI_REVISION 30

/* Symbol/memory-contract revision. Not a JSON-shape revision. This is the
 * revision the LOADED library reports; the block above says why it exists
 * beside a macro that carries the same number. */
int wz_dissect_abi_version(void);

/* Release a string this library returned. Null is a no-op. */
void wz_dissect_string_free(char *s);

/* Dissect ONE transport message. `base` is the coordinate spans are
 * reported in: pass the message's offset within a capture for capture
 * offsets, or 0 for message-relative ones.
 *
 * This door reads a message with NO session. A bare network message of a
 * session that negotiated LowLatency -- every data message after its
 * handshake -- is therefore a MID the transport space does not name, and reads
 * as `Unknown`; hand such a message, with its flow's `context`, to
 * wz_dissect_transport_message_in below. */
int wz_dissect_transport_message(const unsigned char *bytes, size_t len,
                                 size_t base, char **out);

/* ABI 27 -- ONE message, read in the light of the session it came out of.
 *
 * THE GAP. wz_dissect_transport_message has no session, and that is its
 * contract. It is wrong for exactly one kind of message. On a session that
 * negotiated LowLatency there is no Frame around the data, so the first byte of
 * a message after the handshake is a NETWORK header; read as a transport header
 * it is a MID the transport space does not name, and the answer is the
 * `Unknown` group: `header`, `mid`, `z` and the rest of the message as one
 * `body`. That is accurate and it is not usable, because the keyexpr, the put
 * and the payload are then one blob. Init, Open, KeepAlive and Close read
 * without a session, and so do the Frame and Fragment messages of a session
 * that did not negotiate LowLatency. The session's field document reads the
 * same bytes in full, because it knows the context. This door takes the context
 * and gives the same answer.
 *
 * `context_json` is the `context` object of one flow of the field document
 * (wz_dissect_pcap_fields and its siblings), as that document writes it,
 * NUL-terminated UTF-8:
 *
 *     {"phase":"closed","negotiated":true,"lowlatency":true,...}
 *
 * WHAT IT READS FROM THE CONTEXT. Two keys: `negotiated` (a boolean) and
 * `lowlatency` (a boolean or null). Both must be present and of that type.
 * Every other key is ignored whatever its value or type, so a context that has
 * grown a key, or retyped one this door does not use, still opens.
 *
 *   negotiated true, lowlatency true
 *       A message whose first byte is a NETWORK MID (the low five bits are
 *       0x19 to 0x1F: Interest, ResponseFinal, Response, Request, Push, Declare,
 *       Oam) is read as the network message it is, with its whole field tree.
 *       Any other first byte is read as a transport message, which is how Init,
 *       Open, Close and KeepAlive read from the same context as the data. The
 *       MID alone decides: the transport and network MID spaces do not overlap.
 *
 *   lowlatency false or null, or negotiated false
 *       UNKNOWN to this door, and the reading is wz_dissect_transport_message's,
 *       byte for byte. A capability nobody agreed is not assumed, so a `true`
 *       beside `negotiated: false` -- what a half-seen handshake would fold to
 *       -- is not an agreement.
 *
 * WHAT THE OTHER KEYS DO TO A MESSAGE: NOTHING. `compression` wraps a whole
 * BATCH (a batch header byte, then lz4 when its bit 0 is set), and this door is
 * handed one message that is already out of its batch: it opens no batch, and a
 * batch header is not part of a message. `qos`, `patch`, `sn_mask`,
 * `batch_size`, `version` and `phase` judge a message (a priority is
 * meaningful, a size was exceeded, a number has a gap); none of them decides
 * which bytes belong to which field.
 *
 * WHAT THE ANSWER IS. The same node wz_dissect_transport_message returns, and
 * for a message the session document walked it is identical to that row's
 * `fields`: names, kinds, values and spans, the spans in `base`'s coordinate.
 * A message of a lowlatency session after its handshake is one unit holding ONE
 * message, so a network message followed by more bytes is
 * WZ_DISSECT_ERR_DECODE -- the decline the document gives that row -- and not a
 * prefix rendered as a message.
 *
 * WHERE IT PARTS FROM THE DOCUMENT. A first byte in NEITHER MID space, or a
 * transport MID that no lowlatency link carries after its handshake (Frame,
 * Fragment, Join, Oam), is read as a transport message here, as the
 * context-free door reads it. The document knows the message came after its
 * direction's Open and declines such a row; a single message carries no Open to
 * be after.
 *
 * ERRORS. A null `context_json`, `bytes` or `out` is WZ_DISSECT_ERR_INVALID_ARG,
 * and so is a context that is not UTF-8, not JSON, not an object, or whose
 * `negotiated` or `lowlatency` is absent or of another type. A context is
 * produced by code -- the field document writes it -- so a malformed one is the
 * caller's bug and not text an operator typed, which is what separates it from
 * WZ_DISSECT_ERR_SELECTOR. Bytes that do not decode are WZ_DISSECT_ERR_DECODE.
 * Neither hands back a string.
 *
 * Like wz_dissect_transport_message it has no document revision: the answer is
 * a FIELD TREE, not a fixed key set. The memory rule is the usual one: release
 * the string with wz_dissect_string_free. */
int wz_dissect_transport_message_in(const char *context_json,
                                    const unsigned char *bytes, size_t len,
                                    size_t base, char **out);

/* Dissect a classic pcap file held in memory, returning a per-flow SUMMARY.
 * Deliberately a summary: a capture holds an unbounded number of messages
 * and one string carrying all of them is a shape that works for a test and
 * fails for a session. Walk the flows, then expand the messages you want
 * with wz_dissect_transport_message.
 *
 * (summary revision 6) CHECKSUMS, in `health.streams`. Each packet's checksums
 * are counted on three axes: `ip_checksum_*` (the IPv4 header),
 * `transport_checksum_*` (the TCP or UDP checksum) and `tunnel_checksum_*` (a
 * GRE carrier's). Every axis has `valid`, `invalid` and `absent`; the transport
 * axis has a FOURTH key, `transport_checksum_partial`. `absent` means there was
 * nothing to judge: IPv6 has no header checksum, and a UDP datagram over IPv4
 * whose field is zero declined to compute one (RFC 768). The counts are
 * reported and never acted on: a packet that fails still yields its messages.
 *
 * PARTIAL IS A TRANSPORT SEGMENT WHOSE FULL VERIFICATION FAILED AND WHOSE
 * CHECKSUM FIELD EQUALS ITS OWN PSEUDO-HEADER SUM, FOLDED TO 16 BITS AND NOT
 * COMPLEMENTED -- the sum of the source and destination addresses, the
 * protocol and the segment length (RFC 793 for IPv4, RFC 8200 section 8.1 for
 * IPv6). That is the value a sending host leaves in the field when its network
 * card is to finish the checksum, so a capture taken on the sending host
 * (loopback, or any interface whose card does the checksums) holds it in nearly
 * every segment that host sent. The rule is the same for IPv4 and IPv6, for TCP
 * and UDP, and for a segment inside a tunnel.
 *
 * `partial` MEANS NOT VERIFIABLE AT CAPTURE TIME, AND NOTHING ELSE. It is not
 * "good": a segment damaged after the stack wrote the field carries the same
 * value as one that left intact, and no reader of the capture can tell them
 * apart, so it is never counted `valid`. It is not "bad" either, so it is never
 * counted `invalid`, and it is not `absent`. `transport_checksum_invalid`
 * therefore counts only a failing segment whose field is some OTHER value --
 * the evidence of a damaged or forged segment -- and a capture that held real
 * corruption still counts it there. A segment whose genuine checksum happens to
 * equal that sum verifies and is `valid`: the full verification is tried first.
 * A field that is zero, a complemented sum, or a sum over a length other than
 * the one the capture holds is not recognised and reads `invalid`; in
 * particular a segment cut short by a snap length reads `invalid`, as before.
 * Only the Linux loopback shape over IPv4 and TCP has been seen in a real
 * capture; the other families follow the same rule and are tested on built
 * packets.
 *
 * `health.uncorroborated_layers` names the layers on which nothing verified. A
 * LAYER IS UNCORROBORATED WHEN NO CHECKSUM ON IT VERIFIED (`valid` is 0) AND AT
 * LEAST ONE WAS JUDGED, either failed (`invalid`) or `partial`; `absent` counts
 * on neither side. So a capture of a host's own transmit path, in which every
 * segment is `partial`, names `transport`: nothing on it corroborates a
 * payload, which is as true of it as of a capture whose every segment failed.
 * `partial` segments add nothing to `valid` and take nothing from `invalid`, so
 * a layer is judged by its verified and its failing segments as it was before
 * the state existed. The live handle's health document (wz_dissect_live_health)
 * and the command-line report read this one rule and cannot disagree.
 *
 * The revision moved because `transport_checksum_partial` arrived and because
 * `transport_checksum_invalid` stopped counting what is now `partial`. A
 * consumer that read `invalid` as "this reader could not verify it" adds the
 * two. A capture that held no such segment reads exactly as before, with a zero
 * under the new key. */
int wz_dissect_pcap_summary(const unsigned char *bytes, size_t len, char **out);

/* R311y748 (ABI 2) — the same summary, read under BOUNDED memory.
 *
 * wz_dissect_pcap_summary states no caps, so nothing in its
 * health.dropped_by_limits group can ever be non-zero however large the
 * capture is. This one reads under wz's live-tap preset, which is the
 * configuration whose caps bite, so a caller whose memory is finite has a
 * door — and what the bound cost is reported through that same group rather
 * than discarded quietly.
 *
 * A NAMED PRESET and not a limits struct: this ABI hands back a
 * self-describing document instead of a struct tree precisely so that the
 * next axis wz bounds is a preset edit rather than an ABI break.
 *
 * Round 2042 -- and the group carries a `caps` object naming the CEILING each
 * loss was measured against: frames_per_flow, stream_bytes_per_direction,
 * skipped_packets, max_flows_per_table, max_scout_askers. `null` on an axis
 * with no ceiling, never a number and never omitted, so an unbounded run and
 * a bounded one no longer render identically. Before this a `0` said nothing
 * about whether a cap existed to bite, which is the whole distinction this
 * bounded door was added to make. Reading a loss beside its ceiling is also
 * how you tell which cap is NEAREST without waiting for one to bite.
 *
 * R2630 -- and the group counts `scouting`: the SCOUT and HELLO datagrams a
 * `frames_per_flow` ceiling evicted from a flow's scouting list. It shares
 * that ceiling with `frames` and is counted apart from it, so a discovery
 * flow the bound trimmed no longer reads as a flow that lost nothing. It
 * arrived at census revision 12, field-document revision 11 and summary
 * revision 4 -- every document that embeds this group. */
int wz_dissect_pcap_summary_bounded(const unsigned char *bytes, size_t len,
                                    char **out);

/* R311y851 (ABI 3) — the ANALYSIS planes, which this ABI could not
 * reach at all: the keyexpr plane (which keys carry the traffic, with
 * subtree rollups and the declarations still unresolved), the node plane
 * (the capture keyed by zid, and the links where both ends named
 * themselves), the query plane (requests matched to their replies, with the
 * first-reply delay and the ones never answered), and the payload plane
 * (what the samples carry, judged against their own declaration). R311y869
 * added the INTEREST plane (who declared what, and what their declarations
 * cover) and did not reach this paragraph, which is why R2180 struck the
 * cardinal that stood here: ask the document, whose envelope carries the
 * plane list under `planes`.
 *
 * They were never missing from the library — wz-capture is this library's
 * own dependency, so every one was compiled in and had no symbol. What was
 * missing is the door, and a capability a consumer cannot call is one it
 * does not have.
 *
 * The summary above answers the TRANSPORT question and does not carry any
 * of this; ask for the one you want. Four walks of every frame is what this
 * costs, which is why it is a call and not part of the summary.
 *
 * `exchanges` and `payloads` are `null` — not an empty table — in a build
 * whose decoder cannot see the records they correlate. A plane that cannot
 * be fed is absent rather than empty, and `{"rows":[]}` would tell you this
 * capture had no queries in it.
 *
 * SUBSUMED BY wz_dissect_pcap_census_where_limited -- that door takes the
 * selector and the limit preset as ARGUMENTS, so it answers this question and
 * two more. This symbol is kept, not withdrawn: a published symbol is one a
 * consumer already links. New code should reach for the current shape.
 * (R2116, open-debt item 466 -- checked against the library's own `doors`
 * axis, so this line cannot go stale unnoticed.) */
int wz_dissect_pcap_census(const unsigned char *bytes, size_t len, char **out);

/* R311y885 (ABI 7) — the same planes, read under BOUNDED memory.
 *
 * The pairing wz_dissect_pcap_summary_bounded made for the transport
 * document, made here for the analysis one, and this is the half a live tap
 * needs: the census above reads with every cap set to none, which is right
 * for a file that ends and wrong for a link that does not. A framework
 * watching a running system could bound the document it did not need and
 * not the one it did.
 *
 * The same live-tap preset, for the same reason: a preset is an edit and a
 * limits struct across this boundary would be a break.
 *
 * The census document carries dropped_by_limits as of this revision -- the
 * same group the summary reports, from the same emitter -- so a plane made
 * short by an evicted flow says so instead of reading as a quiet network.
 * That key is present through BOTH census doors; behind this one it can be
 * non-zero.
 *
 * wz_dissect_pcap_census_where stays unbounded. Bounding a narrowed census
 * is a separate decision and is not improvised here.
 *
 * SUBSUMED BY wz_dissect_pcap_census_where_limited -- the preset this door
 * hard-codes is an argument there, which is what stopped a `_bounded` twin
 * being added per document. Kept and still linkable. (R2116, item 466.) */
int wz_dissect_pcap_census_bounded(const unsigned char *bytes, size_t len,
                                   char **out);

/* THE SELECTOR LANGUAGE -- its fields, and how a `zid` value is read.
 *
 * Every door that takes a selector takes this language, and
 * wz_dissect_selector_diagnose says where a text goes wrong. A term is
 * `field op value`; terms join with and / or / not and parentheses. These are
 * the fields, written once, in the order an unknown field's refusal lists them.
 * That list is built from the table the parser reads, so the refusal cannot
 * name a field the parser refuses or omit one it accepts, and a test holds
 * this table to the same one:
 *
 *   key          a keyexpr pattern                           == !=
 *   dir          a or b, either case                         == !=
 *   kind         put del query reply err                     == !=
 *   bytes        an integer                                  == != < <= > >=
 *   time         an integer, ms                              == != < <= > >=
 *   elapsed      an integer, ms since the capture began      == != < <= > >=
 *   offset       an integer, bytes into the framing unit     == != < <= > >=
 *   delay        an integer, ms from the source's stamp      == != < <= > >=
 *   zid          the sender's zid, or a prefix of it         == !=
 *   replies      an integer                                  == != < <= > >=
 *   errs         an integer                                  == != < <= > >=
 *   first_reply  an integer, ms                              == != < <= > >=
 *   completion   an integer, ms                              == != < <= > >=
 *   closed       yes or no (y or n)                          == !=
 *
 * `zid` is read against THE CAPTURE the selector is judged in. A value of
 * eight or more hexadecimal digits that does not spell, in full, a zid that
 * capture names is read as a PREFIX:
 *
 *     - the digits are compared with the zid's WRITTEN SPELLING, the one every
 *       document prints: zenoh's, the little-endian id read as a u128. Zenoh
 *       drops one leading zero nibble when it prints a zid, so a node whose top
 *       byte is below 0x10 is written without that zero, and the digits to copy
 *       are the first of THAT text and not of its 32-digit padded form. Either
 *       case is read;
 *     - a prefix that begins exactly ONE zid the capture names selects as if
 *       that zid had been written whole. A value that spells a zid of the
 *       capture in FULL names it whatever else it is a prefix of, so a selector
 *       written before prefixes existed keeps its meaning;
 *     - a value of fewer than eight digits is a whole zid and nothing else,
 *       exactly as before;
 *     - a prefix that begins TWO OR MORE zids of the capture is AMBIGUOUS.
 *
 * AMBIGUOUS means the reader may have meant either node, so no row can be
 * called a miss: the selector judges NOTHING in that capture, and the terms
 * beside the ambiguous one do not rescue it. In the selection document every
 * row reads `unjudged`; in the census every plane that narrows counts its
 * records `undecided`. The refusal reaches the consumer in the same document,
 * as a top-level key that is ABSENT whenever nothing was ambiguous:
 *
 *     "ambiguous_zid_prefixes":[{"start":7,"end":15,"prefix":"cbf383be",
 *                                "candidates":["cbf383be...","cbf383be..."]}]
 *
 * one object per ambiguous term, in the order the selector writes them.
 * `start` and `end` are the BYTE span of the value in the selector (a quoted
 * value's span includes its quotes), the unit of the verdict's `at` and token
 * spans, so a caret lands on the term. `prefix` is the digits typed, in lower
 * case. `candidates` are the zids it begins, in the spelling the documents
 * print and in the order the capture first named them, which is the order of
 * its nodes plane. The key is on the census document from revision 19 and on
 * the selection document from revision 4.
 *
 * THE UNIT OF THE JUDGEMENT IS THE CAPTURE. The same selector can be ambiguous
 * in one capture and name one node in another, because the zids a prefix is
 * compared with are the ones that capture names. A live handle's capture is
 * what it has read so far, so a prefix that names one node now can become
 * ambiguous when a second node with the same leading digits joins, and the
 * question is asked again each time a document is rendered.
 *
 * The field document (wz_dissect_pcap_fields_where_limited and
 * wz_dissect_live_fields_where) reads each row `unjudged` under an ambiguous
 * prefix as well and does not carry the key: ask the selection or the census
 * door which prefix was ambiguous. */

/* R311y854 (ABI 4) — the same census, NARROWED by a selector in wz's own
 * filter language: `field op value` terms (key == robot/pose, kind == query,
 * bytes > 100, delay >= 10, ...) joined with and / or / not and parentheses.
 * The key term takes zenoh's own keyexpr wildcards; they are not spelled out
 * here because a slash followed by a star ends a C comment.
 * An EMPTY selector selects everything, so this is the identity of the call
 * above rather than a way to get nothing.
 *
 * THREE planes narrow and the NODE plane does not -- a node is not a record
 * the selector's terms describe, which is the same choice `wz-analyze
 * --select` makes. Read `narrowed_by_selector` off each plane rather than
 * inferring it from surviving rows; that inference is the one way to get
 * this wrong.
 *
 * Each narrowed plane carries `selection`: matched, rejected and UNDECIDED.
 * The third is why counts are reported beside the rows -- a keyexpr whose
 * declaration went past before the tap started cannot be judged, and without
 * it a short total reads as a whole one.
 *
 * A selector that does not compile returns WZ_DISSECT_ERR_SELECTOR and no
 * string. For the position, call wz_dissect_selector_diagnose.
 *
 * SUBSUMED BY wz_dissect_pcap_census_where_limited -- same selector, plus the
 * ceiling this door cannot take. A narrowed census over a link that does not
 * end is the case this one leaves unserved. (R2116, item 466.) */
int wz_dissect_pcap_census_where(const unsigned char *bytes, size_t len,
                                 const char *selector, char **out);

/* R311y887 (ABI 8) -- the census with BOTH axes as arguments, and the shape
 * every read door that needs a ceiling takes from here on.
 *
 * Boundedness is orthogonal to everything else a read door varies, so a
 * `_bounded` twin per document multiplies: the summary got one, the census got
 * one, and a narrowed census under a ceiling would have been the fourth name
 * for the fourth combination. The preset is a parameter instead, so the fifth
 * combination needs no fifth name.
 *
 * An EMPTY selector selects everything, so ("", NONE) is
 * wz_dissect_pcap_census, ("", LIVE_TAP) is wz_dissect_pcap_census_bounded and
 * (expr, NONE) is wz_dissect_pcap_census_where. Those three keep their symbols
 * -- a published symbol is one somebody links -- and are not deprecated; they
 * are simply not the pattern a new combination follows.
 *
 * The document carries dropped_by_limits through every one of them, so a plane
 * made short by an evicted flow says so instead of reading as a quiet network.
 *
 * A bad selector is WZ_DISSECT_ERR_SELECTOR; an unknown preset is
 * WZ_DISSECT_ERR_INVALID_ARG. Neither hands back a string.
 *
 * @bound limits work-ceiling -- it bounds the WALK, and what the walk
 * dropped is reported in dropped_by_limits. */
int wz_dissect_pcap_census_where_limited(const unsigned char *bytes, size_t len,
                                         const char *selector, int limits,
                                         char **out);

/* R311y854 (ABI 4) — compile a selector and say what is wrong with it,
 * without a capture.
 *
 * Returns WZ_DISSECT_OK for any readable text and writes a JSON verdict:
 * {"ok":true}, or {"ok":false,"at":N,"message":"..."} where `at` is a BYTE
 * offset into the selector. A refused selector is a successful DIAGNOSIS,
 * not an error, which is why the memory rule is untouched: OK means a string
 * you own, an error means none.
 *
 * `at` is the byte that is wrong, with ONE exception. A selector that ENDS
 * UNFINISHED (`demo`, `kind ==`, `kind == `) is refused at its byte LENGTH,
 * just past its last byte, which is where the next character belongs: 4, 7 and
 * 8 for those three. So 0 <= at <= the selector's byte length, and the
 * `tokens` spans below are unchanged by it: `demo` is still one word spanning
 * 0 to 4. From verdict revision 3; before it the position was the byte where
 * the LAST TOKEN began (`demo` was 0), and a caret drawn from it sat on a word
 * that was complete. When the refusal is an unknown field, its `message` lists
 * the fields of THE SELECTOR LANGUAGE above, `zid` included.
 *
 * The useful moment to ask "is this valid, and if not where" is while the
 * expression is being typed -- before there is a capture to run it against,
 * and long before a caller would want to pay four walks of a file to find
 * out.
 *
 * From verdict revision 2, BOTH branches close with the lexer's
 * own tokens:
 *
 *     ...,"tokens":[{"start":0,"end":3,"kind":"word"},
 *                   {"start":4,"end":6,"kind":"operator"}, ...]}
 *
 * `start` and `end` are BYTE offsets, `end` exclusive, in the unit `at`
 * uses, so a caret and a colour run are placed by one rule. A consumer
 * colouring the selector as it is typed reads these instead of keeping a
 * lexer of its own, which would disagree with this one eventually about
 * where a token begins. On a LEXICAL failure (an unclosed quote, a stray
 * character) the list holds every token before the failure and none after
 * it; on a parse failure every token is there. `kind` is one of:
 *
 *     `word`      an unquoted run: a field name or a value alike -- which of
 *                 the two it is, is the parser's knowledge, and the parser
 *                 may never reach a token the lexer produced
 *     `quoted`    a quoted value, the span including both quotes
 *     `operator`  a comparison: == != < <= > >=
 *     `not`       `not` or `!`      (the span says which was typed)
 *     `and`       `and` or `&&`
 *     `or`        `or` or `||`
 *     `open`      (
 *     `close`     )
 *
 * @values selector_diagnose kind
 * @carries selector_diagnose kind passenger */
int wz_dissect_selector_diagnose(const char *selector, char **out);

/* R311y855 (ABI 5) — THE FIELD LAYER: every message in the capture,
 * dissected into the byte ranges it was decoded from.
 *
 * The summary above tells you to "walk the flows, then expand the messages
 * you want" with wz_dissect_transport_message. That walk was not possible:
 * the summary reports per-flow frame COUNTS, and a stream message's bytes
 * live in the REASSEMBLED per-direction stream, which exists only inside
 * this library -- so a caller holding the capture file cannot slice one out.
 * This call does the walk where the reassembly is and hands back the trees.
 *
 * Spans inside a tree are MESSAGE-RELATIVE. Where the message sits is on the
 * row: a stream row carries `message_at`, a byte offset into that
 * direction's retained stream, so a span added to it is a capture
 * coordinate; a datagram row carries `packet`, an INDEX, which must not be
 * added to anything. `offset_space` says which -- they are small numbers all
 * round and cannot be told apart by looking.
 *
 * Every row is a tree OR a `declined` string with the reason. The walk is
 * checked against the session that framed the message, so a coordinate that
 * does not name the message the session framed yields a refusal rather than
 * a confident tree about other bytes. Bytes a bounded read trimmed decline
 * the same way.
 *
 * max_messages_shown_per_flow: 0 is UNBOUNDED, matching the command line's
 * default, and a capture holds an unbounded number of messages -- pass a
 * bound if you have a screen to fill. Each flow reports `shown` and
 * `omitted`, so a held-back listing is never mistaken for a capture that
 * ended. `capture_reread` reports whether the datagram half could read the
 * file a second time, which it must do to reach a datagram message's bytes.
 *
 * SUBSUMED BY wz_dissect_pcap_fields_where_limited -- R2766 moved this line,
 * because a door has ONE current shape and the field family's moved on. That
 * door takes the DISSECTION ceiling this one has no way to state (the bound
 * here trims the listing after the whole walk is already built) AND a
 * selector, so it answers this question and two more. Kept and still
 * linkable. (R2116, item 466.)
 *
 * @bound max_messages_shown_per_flow trims-output -- the whole walk is paid
 * for and only the DOCUMENT is shortened; each flow's `shown` and `omitted`
 * report the trim. (R2120, item 467: the old spelling promised a ceiling
 * this argument has never enforced.) */
int wz_dissect_pcap_fields(const unsigned char *bytes, size_t len,
                           size_t max_messages_shown_per_flow, char **out);

/* R311y856 (ABI 6) — THE FIELD LAYER WITH THE APPLICATION PAYLOADS DECODED,
 * under a mapping you declare.
 *
 * The command line has decoded payloads since R311y699 and this ABI could
 * not: the decoders lived in that binary, which this library must not depend
 * on. They moved beside the map; this is the door.
 *
 * declarations: one per line, NUL-terminated, in the spelling the command
 * line's two flags already write --
 *
 *     demo/temp=protobuf         a format rule: which decoder reads this
 *                                topic's payload
 *     demo/temp:1=temperature    a field name: protobuf's wire format
 *                                carries none, so a deployment that has a
 *                                schema declares it
 *     #profile=c:u16be,f:u8      R2114 -- a format DEFINITION: a record this
 *                                library does not ship, described so a rule
 *                                can name it like any other format
 *     #demo-a={...}              field-document revision 34 -- an end-to-end
 *                                protection PROFILE: the JSON description
 *                                wz_dissect_e2e_open takes, on ONE line,
 *                                registered under a name that must be its
 *                                own `name`. A value that opens with a brace
 *                                is a profile; a record layout never does.
 *     demo/pose=demo-a           a rule that names a profile: the frames
 *                                published under this key are read and judged
 *                                under it (the `e2e` block described above)
 *     demo/pose=demo-a@pkg.Pose  the same, naming the BODY SCHEMA the bytes
 *                                after the header are an instance of. It is
 *                                carried to the row as `body_schema` and
 *                                nothing reads it yet
 *
 * A profile rule competes with the other rules like any rule: the first one
 * that covers a key decides, so a `json` rule ahead of it keeps that key out
 * of the block. The body after the header is also walked as protobuf, so
 * `payload_decode` shows its fields (spans in payload coordinates). A profile
 * is registered ONCE per call, with the declarations text every door below
 * takes, and its judgement state lives for that call: pass the same text to
 * every call of a live handle.
 *
 * THE DEFINITION IS WHY THIS DOOR TAKES TEXT AND NOT A FUNCTION POINTER.
 * A deployment with its own profile table used to have to build this
 * workspace to see its own payloads; the obvious remedy -- register a decoder
 * callback -- would have voided the memory rule at the top of this header,
 * which says no callbacks run. Data can be versioned, diagnosed before there
 * is a capture, and refused by line. Code cannot.
 *
 * A layout is `<name>:<type>` items separated by commas, read in order from
 * byte zero. Types are fixed-width integers and floats with their endianness
 * in the spelling, `bytesN` for N raw bytes, and `rest` -- legal only last --
 * for a variable tail. Ask wz_dissect_readable_surfaces for the spellings
 * this build reads rather than copying a list into your own notes. A field's
 * declared NAME is the path it is reported under.
 *
 * Bytes the layout does not account for are a FINDING and not a quiet
 * success: a short description over a long record decodes every field it
 * names and none of them are wrong, which is the worst way to be looking at
 * the wrong record.
 *
 * A definition may appear before or after the rules that use it, and it may
 * not take a name this build already ships -- redefining one would change
 * what every other config file's rules mean on this run alone.
 *
 * A topic whose own name carries `:` or `=` (or a leading `#`) is written
 * with a backslash before it.
 *
 * Patterns are zenoh's own keyexpr dialect, so a wildcard chunk covers a
 * subtree -- deliberately not spelled here, because that token cannot be
 * written inside a C block comment. ONE dialect for both surfaces, so a rule
 * tried in a terminal and then moved into a config file is not re-spelled.
 * An EMPTY text declares nothing, which makes this the same question
 * wz_dissect_pcap_fields answers.
 *
 * A declaration this build cannot install -- an unknown format name, a
 * pattern this build's matcher has no arm for, a line that is not a
 * declaration -- returns WZ_DISSECT_ERR_DECLARATION and no document. Not
 * skipped: a map quietly smaller than the text that built it leaves a reader
 * blaming the traffic for their own rule.
 *
 * Every walked row gains `payload_decode`, an object whose `state` is
 * `decoded`, `refused`, `encoding_mismatch`, `no_rule`, `keyexpr_unresolved`,
 * `not_on_the_wire` or `no_payload`. The last three are ANSWERS, not
 * omissions: a rule that
 * never fired and a rule that fired and found nothing send you to opposite
 * places, and `keyexpr_unresolved` is the ordinary shape of a capture that
 * began after the declarations went past. A decoded field's start/end are in
 * the MESSAGE's coordinate space, like every other span on the row.
 *
 * R2170 (open-debt item 546) -- `not_on_the_wire` is the eighth state, and it
 * exists because the seventh was giving a FALSE answer in its place. A record
 * whose payload slot holds an SHM descriptor refers to data shared out of
 * band, so this capture never held it; that used to be reported as
 * `no_payload`, which is not a silence but a confident wrong statement about a
 * record that does carry a payload slot. It additionally carries
 * `descriptor_bytes`, an integer: the descriptor's own length, which is the
 * one quantity this plane genuinely has. Nothing is claimed about the data --
 * no decode, no corroboration, no refutation -- because it was never seen.
 *
 * It is reported whether or not the reader declared any format. The fact does
 * not depend on the rules, so it is not gated behind them: a consumer that
 * passed no `--payload` mapping still gets this state, where every other
 * non-`decoded` state above presupposes a rule.
 *
 * @values fields state
 *
 * R311y873 -- `encoding_mismatch` is the sample's OWN declared encoding
 * disagreeing with the rule, and it carries `declared` rather than `why`.
 * Told apart from `refused` because the two send you to opposite places:
 * that one says the bytes are not this format, this one says the bytes are
 * exactly what their publisher said and the MAPPING is wrong. Folding the
 * two would send an operator to a wire with nothing to answer for.
 *
 * Round 2025 (item 285) -- `encoding_mismatch` additionally carries
 * `declaration_checked`, a boolean, and it is the difference between a
 * finding and a default. `true` means the bytes were inspected and they bear
 * the publisher's label out, so the mapping really is the thing that is
 * wrong. `false` means the label is BINARY or unknown -- `application/cdr`,
 * which is what every ROS 2 publisher declares -- so nothing could weigh it
 * and the veto is this reader's policy rather than a measurement. The
 * outcome is the same either way and the warrant is not: an operator whose
 * CDR traffic is being withheld under a protobuf rule can now see that
 * nothing checked the label it is being withheld on. An ADDED key, so a
 * consumer that does not read it is unaffected.
 *
 * R311y874 -- a `decoded` block additionally carries `despite_encoding`: the
 * name the publisher declared when the rule was applied OVER that
 * declaration, and `null` on an ordinary decode. It is non-null exactly
 * where the publisher's own bytes refute its own label -- your rule was
 * right and the topic is mislabelled -- because a declaration this reader
 * can prove false must not veto the rule. Always present, never omitted: a
 * consumer that had to test for the key would read its absence as "nothing
 * was overridden", which is the assumption the field exists to stop.
 *
 * WHICH RULE WON, at field-document revision 28. The states that asked your
 * rules (`decoded`, `refused`, `encoding_mismatch` and `no_rule`) carry
 *
 *     `matched_rule`  {"index":N,"pattern":"..."}, or `null` in `no_rule`
 *
 * The rules are tried in the order you declared them and the FIRST that covers
 * the key wins. `index` is that rule's position among the format rules, from
 * 0, in that order, and `pattern` is its key expression as you mean it (quotes
 * removed). It is NOT a line number: a field-name declaration or a format
 * definition between two rules does not move it. wz_dissect_declarations_diagnose
 * reports the same number as `rule_index` on the line that installed the rule,
 * so a row joins to its line by equality. Two overlapping rules of one format
 * gave byte-identical rows in either order, and a row could not say which had
 * decided it. `null` in `no_rule` is "no rule won", written where the winner is
 * read from; the four states that never asked the rules (`keyexpr_unresolved`,
 * `no_payload`, `not_on_the_wire` and `no_rules`) carry no `matched_rule` at
 * all. Each entry of `payload_mapping` and `payload_refusals` carries the same
 * object, so the rule a finding says to fix is named.
 *
 * HOW A DECODED FIELD IS NESTED, at the same revision. Each entry of a
 * `decoded` block's `fields` also carries
 *
 *     `depth`   0 for a top-level field, 1 for one inside it, and so on
 *     `parent`  the `path` of the field it is nested in, or `null` at depth 0
 *
 * so a consumer drawing a tree never reads the path grammar to indent one. A
 * protobuf message has no root row, so its first-level fields are depth 0; a
 * JSON or CBOR document is rooted at `$`, so the document's own row is depth 0
 * and its members depth 1. Where a field repeats, every occurrence reports the
 * same `path` and the same `parent`; the spans tell them apart.
 *
 * R311y875 -- the document additionally carries `payload_mapping`, a
 * top-level array summarising what your rules MET. Both findings above are
 * per message, and a capture where one mapping is wrong for every sample on a
 * topic reports it once per row -- in the listing you bound because it is
 * that long. Each entry is one (`keyexpr`, `format`, `declared`) triple with
 * `samples`, and `wrong` says which side to go fix:
 *
 *     `rule`         the publisher declared an encoding your decoder is not
 *                    for AND its bytes bear that out, so nothing was decoded
 *                    and your rule is what is wrong
 *     `publisher`    its declaration contradicts your rule and its own bytes
 *                    refute the declaration, so the rule won, the fields are
 *                    good, and the topic is mislabelled
 *
 * @values fields wrong
 *
 * `note` carries the same sentence the command line prints, so a consumer
 * that only forwards findings does not have to compose one. Always present,
 * empty array when nothing is misbound -- the same rule despite_encoding
 * follows, for the same reason. The tally counts the messages this listing
 * WALKED, so a bound you passed bounds it too; each flow's `omitted` is what
 * makes that legible. The SET is complete for what was walked.
 *
 * Round 2031 -- and `payload_refusals` beside it, the THIRD finding: a rule
 * that was actually applied and whose decoder then REFUSED the bytes. Neither
 * side is caught out by the other there, so it is not a misbinding and does
 * not appear in the array above; until this round it existed only per message,
 * once per row in a listing you bound because it is that long. Each entry is
 * one (`keyexpr`, `format`) pair with `samples`, one sample's reason as
 * `example`, a `note`, and `under` -- what the publisher had said, which is
 * what decides where to look:
 *
 *     `corroborated`  the publisher declared an encoding your rule IS for and
 *                     the decoder still refused; both claims agree and the
 *                     bytes are the odd one out, so look at the capture
 *     `unclaimed`     nothing was declared that this reader could weigh, so
 *                     your rule is the only claim and the traffic contradicts
 *                     it; check the rule first
 *     `refuted`       the publisher declared something its own bytes refute,
 *                     your rule was applied over that label, and it refused
 *                     too -- both are wrong about this traffic
 *
 * @values fields under
 *
 * Always present, empty array when nothing refused, and bounded by the same
 * walk: `payload_mapping_counts_exact` covers BOTH tallies, because being a
 * floor is a property of the walk rather than of either finding.
 *
 * SUBSUMED BY wz_dissect_pcap_fields_where_limited -- R2766 moved this line
 * for the reason the one above it moved: the family has one current shape.
 * That door takes the same declarations text, the dissection ceiling, and a
 * selector, so it is this call with the things it cannot say. Kept and still
 * linkable. (R2116, item 466; R2766, open debt 788.)
 *
 * @bound max_messages_shown_per_flow trims-output -- as above: the walk is
 * paid for in full and `shown`/`omitted` report what the document left
 * out. */
int wz_dissect_pcap_fields_with_payloads(const unsigned char *bytes, size_t len,
                                         size_t max_messages_shown_per_flow,
                                         const char *declarations, char **out);

/* R311y917 (ABI 10) — THE FIELD LAYER UNDER A CEILING, with both of its
 * other axes as arguments.
 *
 * The summary has had a bounded form since ABI 2 and the census since ABI 7.
 * The field layer had none, and it is the plane that walks EVERY MESSAGE of
 * the capture -- so it is the one a live tap can least afford unbounded.
 * max_messages_shown_per_flow is not a ceiling: it trims the OUTPUT after the whole
 * dissection has been built, so asking for ten messages still costs you the
 * whole file.
 *
 * ONE door and not two more twins, on the shape
 * wz_dissect_pcap_census_where_limited settled: an EMPTY declarations text
 * declares nothing, so ("", NONE) is wz_dissect_pcap_fields and
 * (text, NONE) is wz_dissect_pcap_fields_with_payloads. Both of those stay
 * exported -- a symbol this ABI has published is one you may already link.
 *
 * limits is WZ_DISSECT_LIMITS_NONE or WZ_DISSECT_LIMITS_LIVE_TAP. An unknown
 * value is WZ_DISSECT_ERR_INVALID_ARG and never a quiet fall back to
 * unbounded.
 *
 * The field document gained `dropped_by_limits` in the same round -- the same
 * five counters the summary's health object and the census document carry --
 * so a listing made short by an evicted flow says so instead of reading like
 * a capture that ended. Present with every counter zero when no ceiling was
 * asked for, so "no caps" and "caps that did not bite" are distinguishable.
 *
 * THE TWO BOUNDS ON THIS DOOR ARE NOT THE SAME KIND, which is the whole
 * reason it takes both:
 *
 * @bound max_messages_shown_per_flow trims-output -- the DOCUMENT is
 * shortened after the walk; `shown`/`omitted` report it.
 * @bound limits work-ceiling -- the WALK is bounded; dropped_by_limits
 * reports it.
 *
 * SUBSUMED BY wz_dissect_pcap_fields_where_limited -- that door takes a
 * SELECTOR beside everything this one takes, so it answers this question and
 * one more: which of the rows a reader asked for actually matched. This
 * symbol is kept, not withdrawn: a published symbol is one a consumer
 * already links. New code should reach for the current shape.
 * (R2766, open debt 788 -- checked against the library's own `doors` axis,
 * so this line cannot go stale unnoticed.) */
int wz_dissect_pcap_fields_limited(const unsigned char *bytes, size_t len,
                                   size_t max_messages_shown_per_flow,
                                   const char *declarations, int limits,
                                   char **out);

/* R2766 (ABI 17) — THE FIELD DOCUMENT OVER THE MESSAGES A SELECTOR PICKS,
 * with each row saying which way it went.
 *
 * The join of the two doors above it. The census doors took a selector and
 * answered with COUNTS; the field doors emitted rows and took none. A
 * consumer wanting "show me the messages this selector matches" had one
 * option left, which was to take every row back and apply the selector again
 * on its own side — a second implementation of this library's selector
 * language, living in the caller, disagreeing with this one eventually.
 *
 * Given a selector, each message object gains a "selected" key with ONE OF
 * FOUR WORDS, and they are four because two of them would otherwise be one:
 *
 *   `yes` / `no`  the row's records were judged and folded. Any match makes
 *                 the row a match; all misses make it a miss.
 *   `undecided`   records were judged and this capture does not carry what
 *                 deciding needs -- a keyexpr that never bound, an absent
 *                 clock.
 *   `unjudged`    the row carries no record a selector can speak of: Init,
 *                 Open, Close, KeepAlive, Declare and Interest, which carry no
 *                 kind, no keyexpr and no payload, so the word is the same
 *                 under every selector; and a ResponseFinal whose request the
 *                 capture does not hold; and EVERY row, whatever it carries,
 *                 when the selector is AMBIGUOUS in this capture (see THE
 *                 SELECTOR LANGUAGE): a `zid` prefix that begins two or more
 *                 of its zids has no meaning to judge a row by.
 *
 * A caller asking "why did my selector miss this" must be able to tell the
 * last two apart, because only "undecided" is about the selector. The one
 * `unjudged` that is about the selector too is the ambiguous one, and the
 * selection document names it in `ambiguous_zid_prefixes`.
 *
 * WHAT A ROW'S `kind` IS (since field-document revision 27 and
 * selection-document revision 2; before them the rows named below read
 * `unjudged` under every selector). The selector's kind words are put, del,
 * query, reply and err, and a row's kind is the kind of what it carries:
 *
 *   Push           put or del, by its body.
 *   Request        its body's kind. Upstream Zenoh's request body is a query
 *                  and nothing else, so this is `query`; a Request this
 *                  library decodes with a put or a del body, which no peer
 *                  sends, takes that kind.
 *   Response       `reply` when it carries a Reply, WHATEVER the reply carries
 *                  (a reply carrying a put is `reply`, not `put`; ask
 *                  `kind == reply and bytes > 0` for the ones with a payload),
 *                  and `err` when it carries an Err.
 *   ResponseFinal  no kind of its own: it FOLLOWS ITS EXCHANGE. It closes the
 *                  Request with the same request id and answers every selector
 *                  as that Request does: `kind == query` is `yes` and
 *                  `kind == put` is `no` when the request was a query, and
 *                  every record term (key, dir, zid, bytes, time, elapsed,
 *                  offset, delay) is the request's, not the close's.
 *                  When the capture does not hold the request (it began
 *                  mid-exchange) the row is `unjudged`, never `no`.
 *
 * A Request and its ResponseFinal are judged as the EXCHANGE they are, once, at
 * its close: the outcome terms (replies, errs, first_reply, completion, closed)
 * decide on those two rows, as they do in the census's exchange plane. On any
 * other row they are `undecided`, because a push has no outcome.
 *
 * THE UNIT OF A TIME TERM IS THE MILLISECOND, and stays it (see "WHEN A RECORD
 * WAS CAPTURED" above): `time`, `elapsed`, `delay`, `first_reply` and
 * `completion` compare against whole milliseconds, each end of an interval
 * truncated to its millisecond before the subtraction, so a term does not read a
 * record's sub-millisecond digits. The census exchange plane's latency objects
 * carry the unrounded figures beside the millisecond ones:
 *
 *     "first_reply":{"count":N,
 *                    "min_ms":N|null,"max_ms":N|null,"mean_ms":N|null,"total_ms":N,
 *                    "min_ns":N|null,"max_ns":N|null,"mean_ns":N|null,"total_ns":N}
 *
 * since census revision 17, and the same for `completion`, in every row and in
 * the totals. The `*_ms` keys are what they were. The `*_ns` keys are the SAME
 * samples measured as the difference of the two ends' nanosecond readings, with
 * nothing truncated, so a round trip of 0.575 ms is `575000` in `total_ns`
 * wherever in a millisecond it fell, where `total_ms` is 1 or 0 by where it
 * fell. `mean_ns` is `total_ns` over `count`, truncated to a whole nanosecond,
 * and is the mean to take: a mean of `*_ms` figures is a mean of whole numbers
 * each wrong by up to a millisecond. They are `null` (and `total_ns` is 0) when
 * nothing was sampled, exactly as the `*_ms` keys are, and they follow the
 * integer rule above. An interval whose reply is stamped before its request
 * inside one millisecond is a 0 ms sample and a 0 ns one; one whose reply reads
 * an EARLIER millisecond than its request is not sampled and is counted in
 * `gaps.non_monotonic`, as it was.
 *
 * THE TWO PLANES AGREE. For any selector, on a capture where each row carries
 * one record, the number of `yes` Request rows is the census exchange plane's
 * `requests` and the number of `yes` ResponseFinal rows is its `completed`.
 * Those are different counts and the rows keep them apart: an exchange the
 * capture never saw close has its Request row and no close row.
 *
 * AN EMPTY SELECTOR IS THE IDENTITY, as it is for every census door: it
 * selects everything and asks nothing, so the document that comes back is the
 * one wz_dissect_pcap_fields_limited returns for the same cap, declarations
 * and limits, byte for byte, and no row carries a "selected" key -- a verdict
 * answers a question and none was asked. Absence of the key is the fourth
 * answer, and it is not the same as "unjudged". Whitespace is the same
 * selector as nothing. (An empty selector once wrote "yes" and
 * "unjudged" on every row, against this paragraph. A test now holds every
 * door this header marks SUBSUMED to the same bytes as its successor.)
 *
 * @values fields selected
 *
 * The key and its four words are declared from field-document
 * revision 13. Until then they were written and declared nowhere, so a
 * consumer switching on them had no revision to pin -- a closed vocabulary
 * this header had not marked, which R2175's contract forbids.
 *
 * The verdict is per ROW and not per record: a row may carry several
 * records, and a reassembled record's span exists only inside this library,
 * so a row per record would have to invent a coordinate for each.
 *
 * `selector` is the same language wz_dissect_pcap_census_where_limited
 * takes, and it is refused the same way -- WZ_DISSECT_ERR_SELECTOR, with
 * wz_dissect_selector_diagnose available to say where. `declarations` and
 * `limits` behave exactly as they do for the door above.
 *
 * @bound max_messages_shown_per_flow trims-output -- the DOCUMENT is
 * shortened and the walk is not: every message is still dissected and still
 * judged by the selector, so the verdict counts a reader could derive from
 * the rows shown are a floor. Ask the census door for the totals.
 *
 * @bound limits work-ceiling -- the WALK is bounded, and what it cost is in
 * dropped_by_limits. ⚠ A ceiling that bit under a selector is the case this
 * door most needs a reader to notice: rows the walk never reached are absent
 * rather than unmatched, and "three matched" is not "three matched of what
 * you were shown". */
int wz_dissect_pcap_fields_where_limited(const unsigned char *bytes, size_t len,
                                         size_t max_messages_shown_per_flow,
                                         const char *selector,
                                         const char *declarations, int limits,
                                         char **out);

/* R311y856 (ABI 6) — compile a declaration text and say what is wrong with
 * it, WITHOUT a capture.
 *
 * Always returns WZ_DISSECT_OK for readable text and writes a verdict:
 * {"ok":true,"installed":N,"lines":[...]}, or
 * {"ok":false,"line":N,"text":"...","message":"..."} where `line` counts
 * every line of the text from 0 -- blank ones included, so the number
 * indexes what you sent.
 *
 * The argument wz_dissect_selector_diagnose makes, arriving for the second
 * text a person types. A consumer told only "one of these is bad" makes the
 * operator bisect their own configuration.
 *
 * WHICH KIND EACH LINE WAS READ AS, at verdict revision 2. `lines` has one
 * object per non-blank line, in the order of the text:
 *
 *     {"line":0,"kind":"format_rule","pattern":"demo/temp","rule_index":0}
 *     {"line":1,"kind":"field_name","pattern":"demo/temp"}
 *     {"line":2,"kind":"format_definition"}
 *
 * `line` is the index the failure branch uses. `kind` is one of
 *
 *     `format_rule`        <keyexpr>=<format>
 *     `field_name`         <keyexpr>:<path>=<name>
 *     `format_definition`  #<format>=<layout>
 *
 * `pattern` is the key expression AS READ, with the dialect's quoting removed,
 * and is present for the two kinds that have a key. `rule_index` is present for
 * a `format_rule` only: its position among the format rules, from 0, in the
 * order they are tried (first match wins). It is the `index` of the
 * `matched_rule` a field row reports when that rule decided it, so you join a
 * row to its line by equality and never by counting; a `field_name` or a
 * `format_definition` between two rules does not move it.
 *
 * `installed` counted every line as one declaration whatever its kind, so
 * `a\=b=protobuf` (a rule about the key `a=b`) and `a:b=protobuf` (the name
 * `protobuf` for path `b` under `a`) came back alike. Read `kind`. To write a
 * rule about a key that contains a `:` or an `=`, quote each with a backslash:
 * `a\:b=protobuf` is the rule about `a:b`.
 *
 * @values declarations_diagnose kind
 * @carries declarations_diagnose kind discriminant
 *
 * A KEY THAT IS NOT A KEY EXPRESSION, at the same revision. The failure also
 * carries `pattern` (the key as read), `chunk`, `offset` (a BYTE offset into
 * `pattern`) and `reason`, and `message` is the sentence. They are the keys
 * wz_dissect_keyexpr_diagnose writes for the same text, because it is the same
 * judgement: the one the C drop-in's z_view_keyexpr_from_str asks. A pattern
 * the drop-in refuses is refused here. Six used to install and no longer do:
 * an empty chunk (demo//pose), a question mark, a double star that is not a
 * whole chunk, a star in the middle of a chunk, a double-star chunk followed by
 * another double-star chunk, and a chunk that is only dollar-star. A failure
 * for any other reason carries none of the four.
 *
 * A key with a `:` or an `=` that is NOT quoted is refused as well, because the
 * line does not say whether that separator is the key's own or the dialect's:
 * `a:b:c=x` could be a name for `c` under `a:b`, a rule about `a:b:c`, or a name
 * for `b:c` under `a`. `message` names the separator and its byte. This is a
 * behaviour change for a text that left a reserved character bare in a key.
 *
 * @values declarations_diagnose reason
 * @carries declarations_diagnose reason passenger */
int wz_dissect_declarations_diagnose(const char *declarations, char **out);

/* (ABI 28) -- ONE KEY EXPRESSION, JUDGED, without building a declaration line.
 *
 * Always returns WZ_DISSECT_OK for readable text and writes a verdict:
 * {"ok":true}, or
 * {"ok":false,"chunk":N,"offset":N,"reason":"...","message":"..."} naming the
 * first place the text stops being a key expression. `chunk` counts the
 * `/`-delimited chunks from 0, and `offset` is a BYTE offset into the text: the
 * offending byte for a character, the chunk's first byte for a fault in the
 * chunk's shape, and the text's length for a trailing `/`, where there is no
 * byte to point at. Where a text has several faults the EARLIEST by position is
 * reported. `message` is the sentence a person reads.
 *
 * `reason` is one of upstream's own eight refusals, a closed set:
 *
 *     `empty_chunk`                    an empty chunk: two slashes in a row, a
 *                                      leading slash, a trailing slash, or ""
 *     `star_in_chunk`                  a star that is not a whole chunk (one
 *                                      star, or two) and does not follow a $
 *     `single_star_after_double_star`  a double-star chunk followed by a
 *                                      single-star chunk; write the single
 *                                      star first
 *     `double_star_after_double_star`  two double-star chunks in a row; write
 *                                      one
 *     `lone_dollar_star`               a chunk that is only dollar-star; write
 *                                      a single star
 *     `dollar_after_dollar`            a $ right after a completed dollar-star
 *     `sharp_or_question_mark`         a # or a ?
 *     `unbound_dollar`                 a $ that does not start a dollar-star
 *
 * THE GRAMMAR IS UPSTREAM'S, and it is canonical form: a text that merely
 * CANONIZES is not a key expression. A trailing double-star chunk, a single
 * star before a double star, a leading double star, a double star after a
 * literal chunk, and a dollar-star inside a chunk (a$*b) are key expressions;
 * demo//pose, a slash at either end, a?b, a double star glued to a letter, a
 * star glued to a letter (a*b), two double stars in a row, and a chunk that is
 * only dollar-star are not. The wildcards are legal, since this judges key
 * EXPRESSIONS and not literal keys.
 *
 * ONE VALIDATOR. The verdict is the function behind the C drop-in's
 * z_view_keyexpr_from_str and behind the declaration reader, so the three
 * cannot disagree. wz_dissect_declarations_diagnose used to accept six patterns
 * the constructor refuses, and an editor built on it told a user their pattern
 * was fine; feed this the pattern itself and you do not have to build
 * `pattern=format` to ask, which also reads a `:` in the pattern as a
 * field-name separator.
 *
 * A refusal is a successful DIAGNOSIS, so the memory rule is the one every
 * document door keeps: OK means a string you own, an error means none. Text
 * that is not valid UTF-8 is WZ_DISSECT_ERR_INVALID_ARG.
 *
 * @values keyexpr_diagnose reason
 * @carries keyexpr_diagnose reason passenger */
int wz_dissect_keyexpr_diagnose(const char *keyexpr, char **out);

/* One file of the schema wz_dissect_declarations_from_proto reads. 24 bytes on
 * a 64-bit target, 8-aligned, and like wz_dissect_record it is raw memory a
 * consumer fills by OFFSET, so a change to it is a new struct and a new door,
 * never a new meaning for this one. `the_proto_file_layout_is_pinned` in the
 * Rust crate and an offsetof block in tests/c_abi_consumer.c hold the layout. */
typedef struct wz_dissect_proto_file {
    /* NUL-terminated UTF-8: the name the other files import this one by, and
     * the name a diagnostic carries. Unique within the list. */
    const char *name;
    /* The file's bytes, UTF-8, NOT NUL-terminated. May be NULL only when
     * text_len is zero. */
    const unsigned char *text;
    /* How many bytes `text` holds. */
    size_t text_len;
} wz_dissect_proto_file;

/* (ABI 25) -- A .proto SCHEMA TURNED INTO DECLARATIONS: the field names a
 * protobuf payload's wire format does not carry, as the declaration text the
 * doors above already take.
 *
 * WHY IT IS HERE AND NOT IN YOUR PROGRAM. The wire format carries field
 * numbers and no names, so a payload read under a protobuf rule shows 3.2 where
 * the author wrote temperature. The names are DECLARED, a line each --
 *
 *     demo/temp=protobuf          the rule, first
 *     demo/temp:3=sensor          field 3 is called sensor
 *     demo/temp:3.2=celsius       field 2 INSIDE field 3 is called celsius
 *
 * A person who owns the .proto file should not type those lines, and a program
 * that lets them choose the file must not read .proto itself: that is a second
 * reader of a language inside the process that links this one, and two readers
 * of one language disagree exactly where it is unusual -- a map, a oneof, an
 * import. This is the one reader. What comes back is the dialect the doors above
 * install and wz_dissect_declarations_diagnose validates, and this door runs its
 * own output through that installer before returning it, so the two cannot
 * disagree about what a valid declaration is.
 *
 * THE FILES CROSS AS BYTES YOU ALREADY READ. Nothing here opens a path, and no
 * callback runs: `files` is a list of wz_dissect_proto_file, each a name and a
 * buffer, and `root_file` is the index of the one the user chose. An `import`
 * is resolved BY NAME against that list, by exact string equality, so give each
 * file the name the others import it by (the path protoc would have been given
 * after -I). An import that is not in the list is a diagnostic. Only the root
 * file and what it imports, transitively, are read: a file in the list that
 * nothing imports is never opened and a problem in it is never reported. The
 * well-known types (google/protobuf/timestamp.proto and the rest) are NOT part
 * of this library; a schema that imports one needs it in the list like any
 * other file.
 *
 * `key_pattern` is a key expression AS ITS AUTHOR MEANS IT, not declaration
 * text. The characters that dialect reserves (backslash, colon, equals sign and
 * the hash sign) are quoted for you, so a topic named demo/temp:c needs nothing
 * special. It must not hold a line break. `root_message` is the message the
 * payloads carry, by FULL name including the package: pkg.Outer, or Outer when
 * the file declares no package. It is looked up among the messages of the files
 * that were read.
 *
 * WHAT COMES OUT, in the verdict's `declarations`: the rule line, then one line
 * per field of the root message in declaration order, each ending in a newline.
 * A field's path is its NUMBER, and a field whose type is a message is followed
 * by the lines of that message's fields, their paths the parent's path, a dot
 * and the field number -- the spelling the payload reader gives a nested field,
 * because a declaration is matched to a decoded path by equality of text. A
 * name is the field name as written. A repeated field is one path: the reader
 * reports every occurrence under it. A oneof's members are ordinary fields. An
 * enum-typed or scalar field names itself and nothing under it.
 *
 * A MAP is declared as the repeated entry message it is on the wire, whose key
 * is field 1 and whose value is field 2 (google/protobuf/descriptor.proto, the
 * comment on MessageOptions.map_entry). map<string, Meta> by_tag = 4 emits
 *
 *     demo/temp:4=by_tag
 *     demo/temp:4.1=key
 *     demo/temp:4.2=value
 *
 * and, because the value is a message, the lines of Meta's fields under 4.2.
 * `key` and `value` are the names protoc gives the entry message's fields.
 *
 * Declarations match IN THE ORDER WRITTEN and the first match wins, so text you
 * append after this door's output cannot override it; put what must win ahead.
 *
 * WHAT IS READ: proto2 and proto3 (a file with no syntax statement is proto2,
 * as protoc reads it); package; import and import public; message, nested up
 * to the bound below; enum (its names, to resolve types); oneof; map; the
 * labels; reserved ranges and names; extensions ranges (read and ignored);
 * group fields and extend blocks (see the next paragraph for when they matter);
 * comments and string literals with their escapes. Option
 * statements, [bracketed] options and service blocks are skipped with their own
 * grammar, so a mistake in one is reported at the token that is wrong and does
 * not swallow the statements after it.
 *
 * WHAT IS REFUSED, each with a reason, a file, a line and a column.
 *
 *   - import weak and editions, in any file that is read.
 *   - a group field or an extend block, but ONLY WHERE THE ROOT MESSAGE REACHES
 *     IT. The declarations come from the root message and every message
 *     reachable from it through field types (a map's value type included). A
 *     group is written with the deprecated group wire types, which the payload
 *     reader stops at, and it names a field of the message that holds it; an
 *     extension's fields are declared outside the message they extend, so their
 *     names could not be attached to it. So a group is refused when the message
 *     that holds it is one of those, and an extend block when the message it
 *     extends is, and the refusal names the group or extend keyword's file,
 *     line and column. Anywhere else the block is read for its syntax and
 *     changes nothing: a schema may import a public options file whose extend
 *     blocks add options to google.protobuf.FieldOptions, because no payload is
 *     a FieldOptions. The extended message is looked up as protoc looks it up,
 *     and one that cannot be found is an error here too.
 *   - a recursive message: one whose tree contains itself. Its fields would
 *     need a declaration at every depth, so the cycle is named
 *     (pkg.A -> pkg.B -> pkg.A) and refused, not expanded to a depth nobody chose.
 *   - what protoc itself refuses and this reader needs to be sure of: syntax
 *     errors, a type that is not defined, one defined in a file the referencing
 *     file does not import (an import public is followed), a field number of
 *     zero, above 536870911 or inside 19000 to 19999, a number used twice, a
 *     reserved number or name, a name defined twice, a map key that is not an
 *     integral type or string, a label or an extension range where the syntax
 *     forbids one.
 *
 * The first problem found is the only one reported, in the order protoc meets
 * them: a syntax error before a semantic one, an imported file before the file
 * that imports it. A group or extend block the root message reaches comes
 * after all of those, because which messages the root reaches is known only
 * once every file is read and the root is found, and before the refusals the
 * expansion itself makes (a recursive message, a path too deep, too many
 * lines); of several, the one in the message the expansion visits first is
 * named. THIS IS NOT A VALIDATOR: an enum protoc would refuse for its numbering
 * is accepted here, and so are JSON name collisions and option values, and the
 * fields of an extend block are read for their syntax alone (their numbers,
 * names and types are not judged). A file accepted here can still fail protoc.
 * A file refused here fails protoc too, EXCEPT for the refusals that are about
 * what can be declared and not about the schema being wrong: a group or extend
 * block the root reaches, import weak, a recursive message and the bounds
 * below are all accepted by protoc, and so are editions by a protoc new enough
 * to read them.
 *
 * BOUNDS, all of them refusals and none of them silent truncations: messages
 * written inside one another 31 deep (protoc 3.21's limit: it compiles 31 and
 * refuses 32; older protoc accepts more, and the door refuses past 31 whichever
 * one you have), imports 64 files deep, a field path 64 messages deep, and a
 * result of 16384 lines. The last is not decoration: a
 * schema with no cycle can still expand exponentially, because a message that
 * holds two of a message that holds two of another, twenty times over, is a
 * million paths from a twenty-line file. Work is otherwise linear in the text.
 *
 * THE VERDICT. Returns WZ_DISSECT_OK for any well-formed arguments and writes
 *
 *     {"document":{"name":"declarations_from_proto","revision":1},
 *      "ok":true,"declarations":"demo/temp=protobuf\ndemo/temp:1=value\n",
 *      "installed":2}
 *
 * or
 *
 *     {"document":{...},"ok":false,"file":"a.proto","line":3,"column":9,
 *      "reason":"...","message":"a.proto: line 3: ..."}
 *
 * `installed` is the count wz_dissect_declarations_diagnose reports for the
 * same text. `line` and `column` count from 1 -- they locate a place in a FILE
 * the way every .proto tool does, where wz_dissect_declarations_diagnose counts
 * from 0 because it indexes text you typed into a box. A column counts BYTES
 * from the start of the line, so a tab is one column and a multi-byte
 * character several. `file`, `line` and `column` are present together for a
 * place in a file; `file` alone means the problem is the file as a whole (the
 * root message is not defined in it or in what it imports); none of the three
 * means it is about an argument (a key pattern the declaration dialect cannot
 * install, or one holding a line break). They are ABSENT where they do not
 * apply and never null: a top-level null is what this library reserves for a
 * plane it cannot feed. `message` is the one-line form,
 * `{file}: line {line}: {reason}`, with the parts that are absent left out. A
 * refused schema is a successful DIAGNOSIS, for the reason
 * wz_dissect_declarations_diagnose gives: OK means a string, an error means
 * none.
 *
 * Returns WZ_DISSECT_ERR_INVALID_ARG, and no string, for a null pointer, a
 * file_count of zero, a root_file outside the list, a name or buffer pointer
 * that is null where it may not be (a buffer may be null only when its length
 * is zero, which is an empty file), two files with one name, or a key pattern,
 * root name or file name that is not UTF-8. Those are the caller's bug and not
 * text a person typed; a file whose BYTES are not UTF-8 is a diagnostic, with
 * the place it stops being UTF-8, and only if the file is read. */
int wz_dissect_declarations_from_proto(const char *key_pattern,
                                       const char *root_message,
                                       const wz_dissect_proto_file *files,
                                       size_t file_count, size_t root_file,
                                       char **out);

/* (ABI 29) -- FIELD VALUES, AS JSON, TURNED INTO PROTOBUF WIRE BYTES by the
 * types a .proto schema gives them: the sending half of
 * wz_dissect_declarations_from_proto.
 *
 * WHY IT IS HERE AND NOT IN YOUR PROGRAM. A program that lets a person fill in
 * the fields of a message and then sends it needs the bytes. If it builds them
 * itself it holds a second WRITER of the wire format beside the one reader the
 * door above feeds, and two writers disagree exactly where the format is
 * unusual: a sint32 is zigzagged and an int32 is not, a negative int32 is ten
 * bytes, a proto3 field at its default is absent, a packed field is one
 * length-delimited run, a map's entries have a fixed order. This is the one
 * writer.
 *
 * THE SCHEMA is the list of files the door above takes -- the same
 * wz_dissect_proto_file structure, the same reader, the same rules: an import is
 * matched BY NAME against the list, only the root file and what it imports are
 * read, nothing opens a path, no callback runs, and the well-known types are
 * not part of this library. `root_message` is the message to build, by FULL
 * name including the package (pkg.Outer, or Outer when there is none). What is
 * refused there for being wrong -- syntax errors, a type that is not defined,
 * a number used twice -- is refused here with the same diagnostic. What that
 * door refuses for not being DECLARABLE is not refused here: a recursive
 * message is fine, because the values are finite, and a group or an extend
 * block in the schema matters only if the values name it (see WHAT IS REFUSED).
 *
 * THE VALUES are one JSON object, `values_json`, in protobuf's JSON mapping --
 * the form a person, or another tool, is most likely to already hold.
 *
 *   - A field is written under its name as the .proto file spells it
 *     (sensor_id) or under its JSON name, which is that name in lowerCamelCase
 *     (sensorId) unless the field sets [json_name = "..."]. Naming one field
 *     twice, in either form, is refused, and so is a key that is no field.
 *   - A message is an object, a repeated field an array, and a map<K, V> an
 *     object whose keys are the map keys written as strings ("7", "true").
 *   - int32, uint32, sint32, fixed32, sfixed32 and the 64-bit kinds are a JSON
 *     number or a decimal string; the string is how a 64-bit value survives a
 *     reader that holds numbers as doubles, and the digits are read exactly, so
 *     18446744073709551615 and 9007199254740993 keep every bit. A number must be
 *     an integer (1.0 and 1e3 are, 1.5 is not) that fits the type, and only plain
 *     JSON number grammar is read for it: 0x10, +1 and 01 are refused as
 *     numbers. A string is digits with an optional sign ("-5", "007") and
 *     nothing else; "1.0" and "1e3" are refused, as protobuf's own parser
 *     refuses them, and so is a minus sign in a string for an unsigned type,
 *     even on a zero ("-0").
 *   - float and double are a number, a decimal string, or one of the strings
 *     "NaN", "Infinity" and "-Infinity". A finite value that does not fit a
 *     float is refused, not turned into infinity.
 *   - bool is true or false. string is a string. bytes is a base64 string, in the
 *     standard or the URL-safe alphabet (not both in one string), padded or
 *     not, whose last character carries no bits beyond the data.
 *   - An enum is the NAME of one of its values or an integer (a JSON number, or
 *     a string of digits, which a name cannot be). A proto2 enum is closed, so an
 *     integer that is none of its values is refused; a proto3 enum takes any
 *     int32.
 *   - null means "not set" for a field, and is refused as an array element or a
 *     map value, where there is nothing to leave out.
 *
 * The text is read by the library's one JSON reader, which reads JSON5, so it
 * admits what JSON5 admits (comments, trailing commas, unquoted keys); a number
 * is then held to the strict grammar above. Nesting deeper than 64 levels is
 * refused before the tree is built: the reader recurses once per level, and a
 * text a person chose must not be able to exhaust the stack of the program that
 * linked this library. The well-known types (Timestamp, Duration, Any, the
 * wrappers, Struct) have a special JSON form in that mapping, a string or a
 * bare value, which this library does not read; such a message is written from
 * its fields, as an object, and handed the special form the refusal says so.
 *
 * THE BYTES.
 *
 *   - Fields are written in ascending field NUMBER, whatever the order in the
 *     file or in the JSON, each once.
 *   - A proto3 singular field that is not in a oneof, not `optional` and not a
 *     message is written only when its value is not the default: 0, false, the
 *     empty string or bytes, the enum value numbered zero, or a float or double
 *     whose bits are all zero (so -0.0 IS written, as protoc writes it). A field
 *     with presence is written whenever the JSON gives it: a message field, a
 *     member of a oneof, an `optional` or `required` field, and every singular
 *     field of proto2. Two members of one oneof are refused, and so is a
 *     missing `required` field.
 *   - A repeated numeric, bool or enum field is one length-delimited run of its
 *     elements ("packed") in proto3 unless it sets [packed = false], and one tag
 *     per element in proto2 unless it sets [packed = true]. A repeated string,
 *     bytes or message field is one tag per element. An empty array writes
 *     nothing.
 *   - A map is a repeated field of entry messages whose key is field 1 and whose
 *     value is field 2, both always written, the entries in ascending key order
 *     (numeric for integer keys, false before true, byte order for strings), so
 *     the same values always give the same bytes. An integer key is a string of
 *     digits with an optional sign, and a key given twice, whatever its
 *     spelling ("1", "+1" and "01" are one key), is refused.
 *   - int32 and an enum are the varint of the sign-extended value (a negative one
 *     is ten bytes); sint32 and sint64 are zigzag; fixed32, sfixed32 and float
 *     are four bytes little-endian, fixed64, sfixed64 and double eight.
 *
 * WHAT IS REFUSED, with the place and the type that was expected: a value that
 * does not fit its field's type; a key that is no field (the reason lists the
 * fields there are); a field named twice; two members of a oneof; a missing
 * required field; a null where nothing can be left out; an enum name that is
 * none of its values. And, where the JSON NAMES them and not where the schema
 * holds them, a group field (it is delimited by the deprecated start-group and
 * end-group markers, which the payload reader cannot read back) and an
 * extension written as "[pkg.ext]" (an extension is no field of the message it
 * extends). A [json_name] that is not a string, a [packed] that is not true or
 * false, and [packed = true] on a string, bytes or message field are errors in
 * the SCHEMA, blamed at the option's value: json_name is judged for every field
 * of a message the values reach, since it decides which keys that message
 * answers to, and packed only for a field the values name.
 *
 * WHERE IT DIFFERS FROM libprotobuf's OWN JSON PARSER, measured against
 * JsonToBinaryString of libprotobuf 3.21.12: where both accept a text they
 * agree on the message, and where they differ this door says no and that parser
 * makes something up. A bool given as a string ("true", and also "True" and
 * "yes"), a scalar for a repeated field (it wraps one), a null array element
 * (it drops it) and a null map value (it writes the default) are refused here;
 * so are a field or a map key given twice (it writes both), a float string
 * that is not JSON number grammar (".5", "1.", "+1.5", "0x10": it reads them as
 * strtod does) and an integer for a closed proto2 enum that none of its values
 * has. The other way round, this door admits JSON5 (comments, single quotes,
 * unquoted keys), which that parser refuses.
 *
 * THE FIRST PROBLEM is the only one reported, in this order: an argument (the
 * root file index, a duplicate file name), the schema (in the order the door
 * above gives), the root message, whether the values are JSON, then the values
 * from the top down in the order they are written.
 *
 * BOUNDS, all of them refusals: the message may encode to at most 4194304
 * bytes (a message or a sub-message that grows past it is refused where it
 * does, and the work to find out is linear in the text of the schema and of the
 * values), and the values may nest 64 levels, an object and the array of a
 * repeated field or the object of a map's entries each counting one.
 *
 * THE VERDICT. Returns WZ_DISSECT_OK for any well-formed arguments and writes
 *
 *     {"document":{"name":"proto_encode","revision":1},"ok":true,
 *      "payload":"089601","payload_bytes":3}
 *
 * `payload` is the message's wire bytes as lowercase hex and `payload_bytes`
 * how many bytes that is; an empty message is "payload":"" and 0. A refusal is
 *
 *     {"document":{...},"ok":false,"values_path":"/readings/2/celsius",
 *      "field":"pkg.Reading.celsius","expected":"float: a JSON number, ...",
 *      "reason":"...","message":"values /readings/2/celsius: ..."}
 *
 * and the keys that place it depend on what was refused. The SCHEMA: `file`,
 * `line` and `column` together for a place in a file, `file` alone for the file
 * as a whole (the root message is not defined in it), none of the three for an
 * argument -- the keys, and the counting from 1 and in bytes, are the ones the
 * door above documents. The values are not JSON: `values_offset`, the byte
 * reading stopped at. The values are JSON and do not fit: `values_path`, an RFC
 * 6901 JSON pointer to the place ("" is the whole text; a "/" or "~" in a key is
 * escaped), with `field`, the full name of the schema field the value was for,
 * and `expected`, what would have been accepted there, when the value was for a
 * particular field. Every one of them is ABSENT where it does not apply and
 * never null: a top-level null is what this library reserves for a plane it
 * cannot feed. `message` is the one-line form, `{file}: line {line}: {reason}`
 * for the schema, `values at byte {offset}: the text is not JSON: ...` for text
 * that is not JSON and `values {values_path}: {reason}` for a value. A refusal
 * is a successful DIAGNOSIS, for the reason wz_dissect_declarations_diagnose
 * gives: OK means a string, an error means none.
 *
 * This door builds the BODY of a message and nothing around it: a protection
 * header and its CRC are wz_dissect_e2e_wrap's, which takes the body as bytes.
 *
 * Returns WZ_DISSECT_ERR_INVALID_ARG, and no string, for a null pointer, a
 * file_count of zero, a root_file outside the list, a name or buffer pointer
 * that is null where it may not be (a buffer may be null only when its length
 * is zero), two files with one name, or a root name, values text or file name
 * that is not UTF-8. Those are the caller's bug and not text a person typed.
 * The memory rule does not move: the verdict is a char* released by
 * wz_dissect_string_free. */
int wz_dissect_proto_encode(const char *root_message,
                            const wz_dissect_proto_file *files,
                            size_t file_count, size_t root_file,
                            const char *values_json, char **out);

/* (ABI 26) -- A PROTECTED FRAME BUILT AND OPENED UNDER A PROFILE YOU DESCRIBE:
 * the mechanism of an end-to-end protection header, with none of anyone's
 * constants in it.
 *
 * WHY IT IS HERE AND NOT IN YOUR PROGRAM. A payload can travel behind a
 * protection header: a length, an identifier, a CRC, a message cell and a
 * counter, in an order and at widths that differ from one deployment to the
 * next, with a CRC taken over some of those fields and the body in an order the
 * profile fixes and that is generally NOT the wire order. A program that
 * produces such frames and also analyses them, each with its own copy of the
 * arithmetic, holds two readers of one format, and two readers disagree exactly
 * where a format is unusual: which fields the CRC covers, in which order and
 * byte order, and whether a mask is applied before the bits are cut out of a
 * field or after. These two doors are the one writer and the one reader.
 *
 * WZ OWNS THE MECHANISM, YOU OWN THE CONSTANTS. Nothing about any one protocol
 * is built in. A PROFILE is a JSON text you pass on every call: the header's
 * fields in wire order, the masks and bit ranges, the CRC's six parameters and
 * the order it is fed, and how the length is counted. The doors keep no state
 * between calls, so the profile is chosen per call and two profiles can be in
 * use at once. The only constants this library carries are published CRC
 * definitions, in its tests.
 *
 * THE PROFILE (the masks here are an example's, not any protocol's).
 *
 *     {"name":"demo",
 *      "fields":[
 *        {"name":"crc","bytes":4},
 *        {"name":"length","bytes":2},
 *        {"name":"counter","bytes":2},
 *        {"name":"ident","bytes":4,"xor":"0x0F0F0F0F",
 *         "split":[{"name":"domain","lsb":24,"width":8},
 *                  {"name":"version","lsb":16,"width":8},
 *                  {"name":"msg","lsb":0,"width":16}]}],
 *      "crc":{"field":"crc","width":32,"poly":"0xF4ACFB13","init":"0xFFFFFFFF",
 *             "refin":true,"refout":true,"xorout":"0xFFFFFFFF",
 *             "cover":["length","ident","@payload","counter"]},
 *      "length":{"field":"length","counts":"frame"},
 *      "counter":{"field":"counter","max_gap":10,"timeout_ms":1000}}
 *
 *   - A field is a big-endian unsigned integer of 1 to 8 bytes, laid out in the
 *     order written with no gaps. `xor` (optional) is XORed into it on the
 *     wire. `split` (optional) names bit ranges of its LOGICAL value, `lsb`
 *     counting from the least significant bit. Building ORs the parts at their
 *     `lsb`, then XORs, then writes; opening reads, XORs, then splits. A part
 *     value that does not fit its `width` is refused, never truncated.
 *   - `crc.cover` is the FEEDING ORDER: field names, and "@payload" for the
 *     body. Each covered field is fed as it stands ON THE WIRE (after `xor`),
 *     at its own width, big-endian. The CRC field is never covered and there is
 *     no zero-fill step. `width` is 8, 16, 32 or 64; the CRC field may be wider
 *     than the CRC (zero-extended) but not narrower. The six parameters are the
 *     catalogue's (Cook, "Catalogue of parametrised CRC algorithms"), and none
 *     of them has a default.
 *   - `length.counts` is "frame" (header plus body) or "frame_minus" with
 *     `"fields":[...]` (header plus body less the widths of the listed fields).
 *     Which of the two a sender used is not on the wire.
 *   - `counter` names the field a receiver judges, the largest forward step it
 *     accepts and the silence it tolerates. The doors below do not judge; see
 *     WHAT THIS DOES NOT DO.
 *   - The CRC, length and counter fields carry no `xor` and no `split`, and are
 *     three different fields.
 *
 * Integers in a profile or a values text are JSON numbers (plain decimal) or
 * strings (decimal, or 0x and hex digits), so a 64-bit value survives a reader
 * that holds numbers as doubles. The text is read by the library's one JSON
 * reader, which reads JSON5, and so admits what JSON5 admits (comments,
 * trailing commas, single-quoted strings, unquoted keys); every key and value is
 * then checked strictly. An unknown key, a key written twice, a width that does
 * not fit, overlapping parts, a cover that names no field, an unsupported CRC
 * width and every other malformed shape is refused. So is nesting deeper than 8
 * levels (a profile needs five): the reader recurses once per level, and a text
 * a person chose must not be able to exhaust the stack of the program that
 * linked this library.
 *
 * wz_dissect_e2e_wrap -- the frame for one set of values.
 *
 * `values_json` supplies every field the mechanism does not compute, the
 * counter included: an object keyed by field name, each a number or, for a
 * split field, an object of numbers keyed by part name. The CRC and the length
 * are computed, and supplying either is refused. `payload` is the body, already
 * serialized by you; it may be NULL only when `payload_len` is 0.
 *
 *     {"counter":258,"ident":{"domain":3,"version":7,"msg":4660}}
 *
 * The verdict, with every step so a caller can check the arithmetic:
 *
 *     {"document":{"name":"e2e_wrap","revision":1},"ok":true,"profile":"demo",
 *      "frame":"76a31259001001020c081d3bdeadbeef",
 *      "payload_offset":12,"payload_bytes":4,
 *      "fields":[{"name":"crc","offset":0,"bytes":4,"raw":1990398553,"value":1990398553},
 *                {"name":"length","offset":4,"bytes":2,"raw":16,"value":16},
 *                {"name":"counter","offset":6,"bytes":2,"raw":258,"value":258},
 *                {"name":"ident","offset":8,"bytes":4,"raw":201858363,"value":50795060,
 *                 "parts":[{"name":"domain","value":3},{"name":"version","value":7},
 *                          {"name":"msg","value":4660}]}],
 *      "crc_computed":1990398553,
 *      "crc_fed":[{"item":"length","bytes":2,"hex":"0010"},
 *                 {"item":"ident","bytes":4,"hex":"0c081d3b"},
 *                 {"item":"@payload","bytes":4},
 *                 {"item":"counter","bytes":2,"hex":"0102"}],
 *      "length_field":16}
 *
 * `frame` is the header and the body as lowercase hex. A field's `raw` is the
 * integer on the wire and its `value` the logical value its parts are cut from
 * (`raw` with the `xor` undone). `crc_fed` is what went into the CRC, in order,
 * with the bytes of every header field; the body is counted, not repeated.
 *
 * wz_dissect_e2e_open -- what a received frame says.
 *
 *     {"document":{"name":"e2e_open","revision":1},"ok":true,"profile":"demo",
 *      "payload_offset":12,"payload_bytes":4,
 *      "fields":[ ...as above... ],
 *      "crc_ok":true,"crc_computed":1990398553,"crc_fed":[ ...as above... ],
 *      "length_field":16,"length_expected":16,"length_matches_frame":true}
 *
 * The body is whatever follows the header; its extent is never taken from the
 * length field. THE LENGTH IS INFORMATION, SEPARATE FROM THE CRC VERDICT:
 * `length_field` is what the field holds, `length_expected` what the profile's
 * rule gives for this frame, and `length_matches_frame` whether they agree. The
 * CRC is taken over the length field as it stands on the wire, never over a
 * length recomputed from the frame, so a sender that counts the length by
 * another rule than your profile's still produces frames whose CRC verifies and
 * shows only as `length_matches_frame` false, while damage shows as `crc_ok`
 * false, with the length facts clean unless the length field itself was hit.
 * The pair tells "the sender counts differently" from "bytes were damaged".
 * `crc_ok` compares the CRC field, whole, with the recomputed value.
 *
 * WHAT THIS DOES NOT DO. It does not judge a SEQUENCE of frames (the counter's
 * step, a repetition, the silence between valid frames): that needs state per
 * stream, and which streams a deployment has is yours to decide. The counter is
 * in `fields`, with `crc_ok` beside it, which is what a judge reads. It does
 * not serialize the body, and it does not know which profile a given topic
 * uses: you pass the profile.
 *
 * THE FAILURE MODES are the ones every document door here keeps. A text this
 * library was handed and refused is a successful DIAGNOSIS: both doors return
 * WZ_DISSECT_OK and write
 *
 *     {"document":{...},"ok":false,"profile_path":"/crc/field",
 *      "reason":"...","message":"profile /crc/field: ..."}
 *
 * The text that was refused is named by the key that locates the place:
 * `profile_path` (an RFC 6901 JSON pointer; "" is the document itself) or
 * `profile_offset` (a byte offset, when the text is not JSON at all) for the
 * profile, and `values_path` or `values_offset` for the values. A refusal that
 * is about no text -- a body too long for the length field, a frame shorter than
 * the header -- carries neither. The key is ABSENT where it does not apply and
 * never null: a top-level null is what this library reserves for a plane it
 * cannot feed. `message` is the one-line form.
 *
 * Returns WZ_DISSECT_ERR_INVALID_ARG, and no string, for a caller bug: a null
 * `profile_json`, `values_json` or `out`, a null `payload` or `frame` with a
 * non-zero length, or text that is not UTF-8. The memory rule does not move: the
 * verdict is a `char*` released by wz_dissect_string_free. */
int wz_dissect_e2e_wrap(const char *profile_json, const char *values_json,
                        const unsigned char *payload, size_t payload_len,
                        char **out);
int wz_dissect_e2e_open(const char *profile_json, const unsigned char *frame,
                        size_t frame_len, char **out);

/* (ABI 30) -- A TRANSPORT MESSAGE BUILT FROM THE FIELDS YOU SET, in the framing
 * the link wants, with a report of where each field sits in the bytes.
 *
 * WHY IT IS HERE. wz_dissect_transport_message reads a transport message and
 * nothing built one. A program that has to SEND a message it chose every field
 * of (a conformance tool aimed at its own nodes, checking how a peer handles
 * input that is well formed and unusual) either keeps a second, unpinned
 * understanding of the layout or takes bytes captured elsewhere. This door
 * writes the message through the generated codecs the session and the
 * dissector use, so the layout is read from one place, and it says where each
 * field of what it wrote is, so a caller that wants to change one field never
 * copies an offset or a width by hand. It is the writing half of
 * wz_dissect_transport_message: every unit it builds reads back through that
 * door, to the fields it was given.
 *
 * WHAT IT IS NOT. It builds a message from explicit fields and puts it in a
 * buffer. It has no destination, opens no socket, scans nothing and sends
 * nothing; where the unit goes is the caller's. It has no hidden mode either:
 * a message out of handshake order is a different message you asked for, and
 * a field set to a value no sender would choose is written the way the format
 * writes it, or refused by name if it does not fit.
 *
 * THE DESCRIPTION is a JSON text (read by the library's one JSON reader, as the
 * protected-frame doors above do, so what JSON5 admits is admitted and every key
 * and value is then checked strictly: an unknown key, a key written twice and a
 * value of the wrong type are refused). `message` names the message, and the
 * rest are its fields, none of which has a default you do not know about:
 *
 *     message     keys (required unless marked optional)
 *     init_syn    version, whatami, zid; optional resolution + batch_size
 *                 (together), extensions
 *     init_ack    the same, and cookie
 *     open_syn    lease_ms, initial_sn, cookie; optional lease_unit,
 *                 sn_resolution, extensions
 *     open_ack    lease_ms, initial_sn; optional lease_unit, sn_resolution,
 *                 extensions
 *     frame       reliable, sn; optional priority, sn_resolution, payload
 *     fragment    reliable, more, sn; optional priority, first, drop,
 *                 sn_resolution, payload
 *     keep_alive  (none)
 *     close       reason, session
 *
 * Join and Oam are not built by this door; asking for them is a refusal that
 * says so. `version` and `reason` are one byte. `whatami` is router, peer or
 * client, or the two bits (0 to 3; 3 is the value upstream calls reserved, and
 * is writable). `zid` is 1 to 16 bytes as hex, in WIRE order (the document the
 * dissector writes prints a zid in zenoh's own, reversed, spelling; this key is
 * the bytes). `resolution` is {"frame_sn":W,"request_id":W} with W one of
 * "8bit", "16bit", "32bit", "64bit", and `batch_size` is two bytes; they travel
 * together behind the S flag, and a message with neither has S clear. `cookie`,
 * `payload` and an extension's `zbuf` are hex. `lease_ms` is a lease in
 * milliseconds and `session` is whether a close ends the session (S set) or one
 * link. `reliable`, `more`, `first` and `drop` are booleans (`first` and `drop`
 * default to false; they are a Fragment's two markers, extension ids 2 and 3).
 * `priority` is 0 to 7 and, WHEN GIVEN, is written as the QoS extension even if
 * it is the default priority a session would leave out; leave the key out for
 * no extension. Integers are plain decimal numbers, or strings (decimal, or 0x
 * and hex digits) so a 64-bit value survives a reader that holds numbers as
 * doubles.
 *
 * EXTENSIONS of an INIT or an OPEN are a list, in wire order, of
 * {"id":N,"mandatory":false,"unit":true} | {"id":N,"z64":V} | {"id":N,"zbuf":HEX}:
 * the id is 0 to 15, exactly one body is named, and the encoding bits of the
 * entry's header and the chain bit follow from the body and the entry's place.
 * The door writes an extension of any id with any body, because what a peer does
 * with an extension it did not negotiate is a thing to try; it does not know
 * which are valid for which message. At most 8 extensions (the bound the
 * reader follows, so that the layout of the bytes can be read back).
 *
 * WHAT YOU SET AND WHAT THE DOOR DERIVES. You set every field the wire lets a
 * sender choose. The door derives only what the wire derives from them: the
 * header flags that say a part is present or which variant this is (S from
 * resolution/batch_size, A from init_ack/open_ack, Z from the extension chain
 * or the QoS and marker extensions, R and M from `reliable` and `more`, T from
 * the lease unit, the Close S from `session`), every length (the cookie's, an
 * extension's, the stream prefix), the width of every VLE, and the extension
 * headers. T is the one derived flag you may override: left alone, a lease that
 * is a whole number of seconds travels as seconds (T set, the form every sender
 * in this tree writes), and `lease_unit` "ms" or "s" writes the unit you name
 * ("s" for a lease that is not a whole number of seconds is refused).
 *
 * SEQUENCE NUMBERS AND THE NEGOTIATED RESOLUTION. You always supply sequence
 * numbers (`sn`, `initial_sn`): the door keeps no ring and derives none. You MAY
 * name the ring they live on, as `sn_resolution` (the same four words), and then
 * a sequence number outside it is refused with the largest value the ring
 * holds, and the report names that value and the widest the VLE can become. The
 * rings are the library's own (`sn::mask_from_res`, zenoh-pico `_z_sn_max`):
 * 8bit holds 0 to 127 (a one-byte VLE at most), 16bit 0 to 16383 (two bytes),
 * 32bit 0 to 268435455 (four) and 64bit 0 to 9223372036854775807 (nine).
 * Upstream spells the same four masks
 * (`io/zenoh-transport/src/common/seq_num.rs:17-20`) and casts the last to its
 * 32-bit sequence number type, so on that ring a peer that is upstream zenoh
 * holds 0 to 4294967295. Without the key any 64-bit value is written: the
 * format has no ring of its own, a handshake sizes it.
 * WHICH FIELDS CHANGE WIDTH WITH THE RESOLUTION: only these, and only as the
 * VLE of their value does. `sn` of a Frame and of a Fragment and `initial_sn`
 * of an OPEN are VLEs whose width follows their VALUE, and the resolution bounds
 * the value, so it bounds the width. No transport message has a fixed-width
 * field whose width depends on a resolution; an INIT's own `resolution` is two
 * fields of that message (the bits of `sn_res`) and bounds nothing in it, and
 * the request id the other resolution sizes lives in network messages, which
 * this door carries as opaque `payload` bytes. Upstream reads a sequence
 * number as a 32-bit integer and truncates what is wider
 * (`commons/zenoh-codec/src/core/zint.rs:175-200`), so a value past 2^32 - 1 is
 * written as given and read back differently by that peer.
 *
 * DOES ANY TRANSPORT MESSAGE CARRY AN INTEGRITY FIELD OF ITS OWN? No. Read at
 * the pinned upstream (zenoh 1.10.1), no transport message carries a checksum,
 * CRC, MAC or signature over its own bytes, and none carries a field that a
 * sender computes from the rest of the message to let a receiver detect
 * damage. The places a reader might look, and what they are:
 *   - Frame, Fragment, KeepAlive, Close: header, sequence number, extensions
 *     and payload only (`commons/zenoh-protocol/src/transport/{frame,fragment,
 *     keepalive,close}.rs`); their reserved bits are reserved (reported as such
 *     below), not a check.
 *   - The cookie (InitAck, echoed in OpenSyn) is opaque bytes the ACCEPTOR makes
 *     and later checks: it encrypts its own state with a private cipher and
 *     compares a nonce on the echo (`io/zenoh-transport/src/unicast/
 *     establishment/accept.rs:370-407` and `:486-512`). Nothing on the wire
 *     defines it and a caller cannot compute a valid one; to send an accepted
 *     cookie, echo the one a real InitAck carried.
 *   - The Auth extension (id 3, `init.rs:154`, `open.rs:115`) is a challenge
 *     and response. Its usrpwd method carries an HMAC of the password keyed by a
 *     nonce from the peer (`.../ext/auth/usrpwd.rs:325-331`, checked at
 *     `:420-423`) and its pubkey method an RSA-encrypted nonce (`.../ext/auth/
 *     pubkey.rs:260-335`): a proof of identity, not a protection of the
 *     message that carries it. The Shm (id 2, `init.rs:150`) and MultiLink
 *     (id 4) extensions carry challenges of the same kind.
 *   - The Compression extension (id 6) negotiates an lz4 block with no
 *     checksum (`io/zenoh-transport/src/common/batch.rs:327-340,451-458`), and
 *     the Patch extension (id 7) is a level.
 * A link may carry a checksum of its own (TCP and UDP do, and a normal socket
 * send cannot forge it); that is the link's, outside every unit this door
 * builds. A consumer that was going to build an integrity case for the
 * transport messages can drop it.
 *
 * FRAMING is the second argument, one of
 *
 *   - WZ_DISSECT_FRAMING_DATAGRAM: the message alone. One datagram is one unit
 *     (UDP, multicast).
 *   - WZ_DISSECT_FRAMING_TCP_STREAM: a 16-bit little-endian length, then the
 *     message (`commons/zenoh-protocol/src/transport/mod.rs:36-40`): TCP, TLS,
 *     WebSocket, a QUIC stream. A body over 65535 bytes is refused.
 *   - WZ_DISSECT_FRAMING_LOWLATENCY_STREAM: a 32-bit little-endian length, then
 *     the message, on a streamed link whose session negotiated LowLatency
 *     (`io/zenoh-transport/src/unicast/lowlatency/link.rs:41-50`).
 *
 * The document carries BOTH the unit (what you write to the socket) and the
 * body (the same message without the prefix), whatever the framing.
 *
 * Passing a framing you did not get from these names is WZ_DISSECT_ERR_INVALID_ARG
 * and never a quiet fall back to datagram: a caller that believes it asked for
 * a stream prefix must not be given none.
 *
 * @unknown FRAMING caller-supplied */
#define WZ_DISSECT_FRAMING_DATAGRAM 0
#define WZ_DISSECT_FRAMING_TCP_STREAM 1
#define WZ_DISSECT_FRAMING_LOWLATENCY_STREAM 2

/* wz_dissect_transport_build -- the document.
 *
 *     {"document":{"name":"transport_build","revision":1},"ok":true,
 *      "prefix_bytes":2,"unit":"0600a5053103dead","body":"a5053103dead",
 *      "layout":[{"name":"unit_length","kind":"length","offset":0,"width":2,
 *                 "relative_to":"unit","encoding":"fixed","value":6,"min":0,
 *                 "max":65535,"bit_mask":null,"carrier":null,"stored":null,
 *                 "measures":"body","ring_max":null,"ring_max_width":null},
 *                ...]}
 *
 * for {"message":"frame","reliable":true,"sn":5,"priority":3,"payload":"dead"}
 * as WZ_DISSECT_FRAMING_TCP_STREAM. `unit` and `body` are lowercase hex.
 *
 * THE LAYOUT is the structural report: one row for every field of the message
 * in wire order, derived from the bytes by the same walker that reads them, so
 * an offset or a width is whatever a reader finds there. EVERY ROW HAS EVERY
 * KEY, `null` where a key does not apply to that row, so a consumer reads
 * `bit_mask` of a length or of a flag without asking which it has:
 *
 *   name         the field's name as the dissector gives it, with an extension's
 *                fields qualified by their place (`extensions[1].value`). Unique
 *                in a document.
 *   kind         what the field is; see below.
 *   offset       the byte offset of the field, counted from `relative_to`. For
 *                a bit-field or flag, the offset of the byte that holds it.
 *   width        the field's width in bytes now; for a bit-field, that of its
 *                byte.
 *   relative_to  what `offset` counts from; see below.
 *   encoding     how the integer is laid out; see below.
 *   value        the integer the field holds: a number, or a string past 2^53
 *                (see the integer paragraph above). `null` for a byte string
 *                (zid, cookie, payload, an extension's body).
 *   min, max     the values that keep the field as it is. For a `vle` they are
 *                the smallest and the largest value that encode in exactly
 *                `width` bytes (1 byte: 0 to 127; 2: 128 to 16383; and so on up
 *                to 9 bytes: 2^56 to 2^64 - 1), so a caller replacing the value
 *                with one in this range changes no other byte. For a `fixed`
 *                integer, 0 to the largest value `width` bytes hold. For a
 *                bit-field, the range of `stored`.
 *   bit_mask     for a bit-field or flag, the bits of the byte it owns; `null`
 *                for a field that owns whole bytes.
 *   carrier      for a bit-field or flag, the `name` of the row for the byte
 *                that holds it.
 *   stored       for a bit-field or flag, what its bits hold shifted down: the
 *                number to write back. It differs from `value` where the field
 *                stores a quantity differently from how it is read: `zid_len`
 *                stores the length minus one.
 *   measures     for a length, the `name` of the row whose bytes it counts, or
 *                `body` for the stream prefix.
 *   ring_max     for a sequence number, when you named the ring: its largest
 *                value; otherwise `null`.
 *   ring_max_width  for a sequence number, when you named the ring: the width
 *                in bytes of the VLE at `ring_max`, the widest the field can
 *                become in that session.
 *
 * `kind` is one of `length`, `sequence_number`, `reserved`, `flag` and `other`.
 * A `length` is a count of the bytes that follow (`cookie_len`, an extension's
 * `value_len`, the stream prefix `unit_length`) or one less than one
 * (`zid_len`). A `reserved` row is every bit of a byte that no field of that
 * message owns, which the format writes zero; it is derived as what the other
 * rows leave, so it cannot be typed wrong. A `flag` is a single bit that says a
 * part is present or a variant is taken. `other` is every other field. The
 * words are a closed set the library holds to a walk: a field that does not fit
 * one of the first four is `other`, a word is not added without moving the
 * document revision, and a field name the library has not classified is
 * refused, not defaulted.
 *
 * `encoding` is one of `fixed` (a fixed number of bytes, a byte string at the
 * width it has in this message, or a bit range inside one) and `vle` (a
 * variable-length integer). `relative_to` is one of `unit` (counted from the
 * first byte of the unit as written to the link: only the stream length prefix
 * is placed this way) and `body` (counted from the message's header byte,
 * behind any prefix). In a unit, a `body` row is at `prefix_bytes + offset`.
 *
 * TO REPLACE A FIELD USING ONLY THE REPORT. For a `fixed` row, write the value
 * little-endian into `width` bytes at the offset. For a `vle` row, write a VLE
 * of the value into `width` bytes at the offset: seven bits at a time, least
 * significant first, the high bit of every byte but the last set, and in the
 * ninth byte of a 9-byte VLE all eight bits raw. For a row with a `bit_mask`,
 * write `stored` shifted up into the mask, in the byte at the offset, keeping
 * the other bits. A value in `min`..`max` keeps the field's width. The rows that
 * decide how the REST of the message is read -- a flag that says a part is
 * present (A, S, Z), a length, the message id, an extension's encoding bits --
 * change the reading of what follows when you replace them; that is what they
 * are for, and the report says which they are by their `kind` and name.
 *
 * WHAT THE LAYOUT COVERS. The transport message. A network message carried by a
 * Frame is one row, `payload`, because the carried bytes are the caller's and
 * their layout is a different message's (wz_dissect_transport_message reads it);
 * a Fragment's `payload` is one row likewise. An extension is a header row with
 * its bit-fields and a body: `value` for a z64, `value_len` and `value` for a
 * zbuf, nothing for a unit.
 *
 * @values transport_build kind
 * @values transport_build encoding
 * @values transport_build relative_to
 * @carries transport_build encoding passenger
 * @carries transport_build kind passenger
 * @carries transport_build relative_to passenger
 *
 * A REFUSED DESCRIPTION is a successful DIAGNOSIS: the door returns
 * WZ_DISSECT_OK and writes
 *
 *     {"document":{...},"ok":false,"description_path":"/sn",
 *      "reason":"300 is outside the 8bit ring: a sequence number there is at most 127",
 *      "message":"description /sn: ..."}
 *
 * The place is `description_path` (an RFC 6901 JSON pointer; "" is the document
 * itself) or `description_offset` (a byte offset, when the text is not JSON at
 * all). A refusal that is about no text -- a body that does not fit the stream
 * prefix, or a message built whose report could not be given -- carries neither:
 * the key is ABSENT where it does not apply and never null, a top-level null being
 * what this library reserves for a plane it cannot feed. `message` is the
 * one-line form. A value that does not fit its field is refused at its key and
 * never truncated.
 *
 * Returns WZ_DISSECT_ERR_INVALID_ARG, and no string, for a caller bug: a null
 * `description_json` or `out`, text that is not UTF-8, or a `framing` no
 * constant names. The memory rule does not move: the document is a `char*`
 * released by wz_dissect_string_free, nothing is retained between calls, and no
 * callback runs. */
int wz_dissect_transport_build(const char *description_json, int framing,
                               char **out);

/* R311y913 (ABI 9) — what this build can READ, without a capture.
 *
 * Writes {"link_types":"0 NULL, 1 ETHERNET, …",
 *         "ext_bodies":{"zbuf":"Auth/pubkey, …","z64":"Declare/node_id, …"},
 *         "payload_field_types":"u8, i8, u16le, …",
 *         "payload_formats":["cbor","json","protobuf"]}
 *
 * Revision 5 -- `payload_formats` is the list of payload formats this build
 * decodes without a declared layout, by name, in the order the build lists
 * them. A reader that shows its operator which sub-decoders exist reads this
 * instead of keeping a list of its own, which ages the moment a build gains a
 * format. A name in it is one a payload rule or a declaration may use. It is
 * NOT a closed set a consumer may switch on: it says what THIS build has, and
 * a later build may list more. An addition; nothing retires.
 *
 * R2114 -- the third key is why the document moved to revision 2. A consumer
 * writing a format DEFINITION (see the declarations door above) needs the
 * type spellings before it has a capture to try them on, and a list copied
 * into its own notes ages the moment this table grows. Read the revision off
 * the envelope rather than assuming the key is there.
 *
 * R2175 -- the document is at REVISION 3, and the fourth key is `value_families`:
 *
 *     "value_families":[{"name":"fields","revision":34,"key":"state",
 *                        "values":["decoded","encoding_mismatch",…]}, …]
 *
 * every key in every document whose VALUE this build draws from a closed set,
 * with that set. `name` and `revision` say which document and which revision of
 * it the words belong to. It is the same argument as the key above, one axis
 * over: a consumer that switches on `payload_decode.state` has that vocabulary
 * copied into its own switch, and R2170 widened it under a key that did not
 * move. Compare what you were written against with what this reports and you
 * can SAY there is a word you do not know, instead of meeting it as a
 * fallthrough. See "EVERY DOCUMENT SAYS ITS OWN REVISION" at the top.
 *
 * Two questions `wz-analyze --help` has answered for a while and this surface
 * could not. Both matter for the same reason: an unread capture reports
 * `messages decoded: 0`, and so does a capture with no zenoh traffic in it, so
 * a consumer that cannot ask which link types this build decodes cannot tell
 * its operator to re-capture. Likewise an extension body this build does not
 * open goes out as `value` -- raw bytes -- which reads exactly like "there was
 * no structure here".
 *
 * The strings are DERIVED from the link-type match and the two body dispatches
 * themselves, and are the same strings the terminal prints. A consumer wanting
 * them as lists splits on ", " and cannot be shown a different answer than
 * `--help` gives. */
int wz_dissect_readable_surfaces(char **out);

/* ── R2102 (ABI 11) — THE LIVE DOOR ──────────────────────────────────────
 *
 * Every door above takes a whole capture and hands back a document. That is
 * right for a FILE, which ends, and wrong for a LINK, which does not: a
 * consumer watching a running system could either re-hand the same growing
 * buffer in and pay a full re-dissection per call, or cut the stream into
 * windows and lose every message that straddles a cut.
 *
 * This is the other shape. Open a handle, feed it packets as they arrive,
 * and take the messages that became decodable into a buffer you own:
 *
 *     wz_dissect_live *h;
 *     if (wz_dissect_live_open(WZ_DISSECT_LIMITS_LIVE_TAP, &h)) { ... }
 *     for (;;) {
 *         wz_dissect_live_push(h, link_type, ts_ns, pkt, pkt_len);
 *         wz_dissect_record buf[256];
 *         size_t n;
 *         while (!wz_dissect_live_drain(h, buf, 256, &n) && n) {
 *             ...                        // render buf[0..n]
 *             if (n < 256) break;        // a short count means drained
 *         }
 *     }
 *     wz_dissect_live_close(h);
 *
 * READ THE MEMORY RULE AT THE TOP OF THIS FILE FIRST. This family is the
 * one exception to it, the exception is stated there, and nothing else in
 * this header creates anything you have to give back except a char*.
 */

/* A live dissection. Opaque: its size and contents are this library's, and
 * a consumer holds only the pointer. */
typedef struct wz_dissect_live wz_dissect_live;

/* The `ts_ns` you pass when you have no clock reading, and the value a
 * record carries back when nothing timed it.
 *
 * NOT zero, and that is the whole reason it is spelled out: zero is a legal
 * instant, and a sentinel colliding with it would report a tap whose clock
 * starts at zero as a tap with no clock.
 *
 * @unknown NO not-an-enumeration */
#define WZ_DISSECT_NO_TIMESTAMP UINT64_MAX

/* wz_dissect_record.kind — the message kinds. Derived from the decoder's
 * own variants (`InboundFrame::kind_code`), so a kind this build gained
 * appears here and in that match on the same commit.
 *
 * 0 and 255 sit at the ends deliberately. UNDECODABLE is not a message kind
 * at all -- it is this reader failing -- and UNKNOWN is a MID this build
 * does not recognise, which is a fact about the wire. Both are answers, and
 * neither is the absence of one. The numbers in between are contiguous so a
 * kind added later gets the next one and a consumer's switch falls through
 * to its own default rather than onto a neighbour's case.
 *
 * R2173 — AND WHAT THAT DEFAULT MEANS, which this block used to stop short of.
 * A kind number this header does not list is the THIRD not-knowing named at
 * the top of this file: the library is NEWER than your header. It is NOT
 * UNKNOWN. UNKNOWN is a fact about the WIRE that wz measured and is reporting;
 * a default is a fact about your own build being older than the library it
 * linked. Folding the second into the first would report strange traffic where
 * there was none.
 *
 * @unknown KIND newer-build
 * @unknown-sentinel KIND UNKNOWN */
#define WZ_DISSECT_KIND_UNDECODABLE 0
#define WZ_DISSECT_KIND_INIT 1
#define WZ_DISSECT_KIND_OPEN 2
#define WZ_DISSECT_KIND_CLOSE 3
#define WZ_DISSECT_KIND_KEEPALIVE 4
#define WZ_DISSECT_KIND_FRAME 5
#define WZ_DISSECT_KIND_FRAGMENT 6
#define WZ_DISSECT_KIND_JOIN 7
#define WZ_DISSECT_KIND_OAM 8
/* Bare network envelope on a negotiated lowlatency link; no Frame or SN. */
#define WZ_DISSECT_KIND_NETWORK 9
/* The SCOUTING namespace's two messages, on records whose origin
 * is WZ_DISSECT_ORIGIN_SCOUTING. They share this one kind space rather than
 * starting their own at 1, because a consumer switches on `kind` alone and a
 * Scout numbered 1 would land on its Init case: the wire bytes are 0x01 in
 * both namespaces, and which one is meant is exactly what the numbers must
 * not leave to the switch. UNKNOWN (255) on a scouting record is a MID this
 * build does not know in that namespace; UNDECODABLE (0) is the same failure
 * it is everywhere. The next transport kind takes 12. */
#define WZ_DISSECT_KIND_SCOUT 10
#define WZ_DISSECT_KIND_HELLO 11
#define WZ_DISSECT_KIND_UNKNOWN 255

/* wz_dissect_record.origin — which of a flow's message lists this came
 * out of. A flow can carry several at once (a UDP conversation may hold
 * cleartext datagrams AND messages recovered from inside QUIC), and they
 * are different lists rather than one interleaved one.
 *
 * R2173 — an origin this header does not list means the library is NEWER than
 * your header; wz assigns this field from a match over its own list types and
 * has no "I could not tell" to report, so unlike KIND there is no sentinel
 * value here and none is missing. Group such a record under whatever your UI
 * calls "another list of this flow" -- not under an error.
 *
 * @unknown ORIGIN newer-build */
#define WZ_DISSECT_ORIGIN_STREAM 1
#define WZ_DISSECT_ORIGIN_DATAGRAM 2
#define WZ_DISSECT_ORIGIN_QUIC_STREAM 3
#define WZ_DISSECT_ORIGIN_QUIC_DATAGRAM 4
#define WZ_DISSECT_ORIGIN_SERIAL 5
/* A datagram flow's SCOUTING list: Scout and Hello, the messages
 * sent BEFORE any session. wz_dissect_live_drain hands them out after every
 * other list, under the same watermark rule, on the datagram flow's flow_id
 * and a list_id of their own. `anchor` is the packet index
 * (WZ_DISSECT_ANCHOR_PACKET), the unit is the whole datagram so batch_index
 * and unit_offset are 0, `flags` is 0 because every flag is a verdict about a
 * session, and `kind` is WZ_DISSECT_KIND_SCOUT / _HELLO / _UNKNOWN /
 * _UNDECODABLE. wz_dissect_live_message_bytes answers
 * WZ_DISSECT_ERR_NO_BYTE_SOURCE for them, as it does for any datagram: the
 * bytes are the packet you pushed. A build whose header predates this value
 * groups these records under "another list of this flow", as the policy above
 * says -- which is what they are. */
#define WZ_DISSECT_ORIGIN_SCOUTING 6

/* wz_dissect_record.anchor_space — how to read `anchor`. They are small
 * numbers either way and cannot be told apart by looking, which is why the
 * record says. A PACKET index must not be added to anything.
 *
 * R2173 — an anchor space this header does not list means the library is NEWER
 * than your header. This is the family where guessing costs the most: the
 * whole point of the field is that the two spaces cannot be told apart by
 * looking, so a consumer that treated an unknown space as either of the two it
 * knows would do arithmetic on a coordinate whose units it does not have. Do
 * not compare or subtract such an anchor; show it and say the space is one
 * this build does not know.
 *
 * @unknown ANCHOR newer-build */
#define WZ_DISSECT_ANCHOR_PACKET 0
#define WZ_DISSECT_ANCHOR_STREAM_BYTES 1

/* wz_dissect_record.flags — zero for an ordinary message.
 *
 * R2173 — and this family answers not-knowing DIFFERENTLY from the enumerated
 * ones, which is why it gets its own policy rather than a reserved member. A
 * flags word is a SET, not one value: a bit this header does not name is a
 * remark the library is making that your build has no use for, and IGNORING IT
 * is correct. Mask with the bits you know (`flags & WZ_DISSECT_FLAG_*`) rather
 * than switching on the word. Adding a "reserved" member here would have been
 * the wrong fix -- it would name a value, and there is no value to name.
 *
 * @unknown FLAG ignore-bits */
/* The frame's wire length exceeded the batch_size its session's InitAck
 * agreed to: a protocol violation by the sender. The message still
 * decoded, and is reported rather than dropped -- dropping is what makes a
 * non-conforming peer invisible. */
#define WZ_DISSECT_FLAG_EXCEEDS_NEGOTIATED_BATCH 0x1u
/* This message cannot occur on the link that carried it (an INIT or OPEN on
 * a multicast-capable link), so it was decoded and reported but NOT folded
 * into the session context. */
#define WZ_DISSECT_FLAG_INADMISSIBLE_ON_LINK 0x2u
/* The first message after the reader recovered its framing. Whatever stood
 * between the loss and this message was skipped. */
#define WZ_DISSECT_FLAG_AFTER_RESYNC 0x4u

/* ONE decoded transport message.
 *
 * 56 bytes, 8-aligned, with every field explicitly sized. Both sides assert
 * that -- `the_record_layout_is_the_one_the_header_declares` in the Rust
 * crate and a sizeof/offsetof block in tests/c_abi_consumer.c -- because
 * this is the one output of this library that is raw memory rather than
 * text: a field inserted or widened gives a consumer plausible garbage (an
 * anchor that is half a timestamp) with no error anywhere.
 *
 * The `_v1` is the compatibility statement. A field read by OFFSET cannot
 * tolerate an unknown one, so a layout change is a new struct and a new
 * door, never a new meaning for this one. */
typedef struct wz_dissect_record {
    /* When this message was CAPTURED, in nanoseconds: the instant of the packet
     * that carried its first byte (the byte its field row's `first_byte`
     * names), or WZ_DISSECT_NO_TIMESTAMP if no clock was ever set. Three
     * things, and the first two look alike:
     *
     *   - it is the capture's own time for the message, to the nanosecond you
     *     pushed it at (a classic pcap's microsecond fraction, widened). It is
     *     NOT the clock as of the moment this reader decoded the message: a
     *     message decoded from bytes that waited behind a hole in a TCP stream
     *     carries the instant of ITS packet, and not the instant the capture
     *     ended. Until field-document revision 31 this field held that
     *     decoding-time clock truncated to the millisecond it fell in, so it
     *     ended in six zeros; it keeps every digit now, and a consumer that
     *     divided it by a million sees what it always saw;
     *   - a push carrying WZ_DISSECT_NO_TIMESTAMP leaves the clock WHERE IT
     *     STOOD, so a record can carry the instant of an earlier packet.
     *     That is a different fact from having no clock, and only the
     *     second reports the sentinel;
     *   - sort on it for time order, and read wz_dissect_live_drain for what
     *     equal values mean. */
    uint64_t ts_ns;
    /* The CONVERSATION: a number this handle assigns each flow it sees, from
     * zero, in order of first appearance. Stable for the life of the handle,
     * meaningless outside it.
     *
     * Everything one UDP conversation carries shares this -- the cleartext
     * messages and whatever was recovered from inside QUIC alike -- because
     * that is what grouping by "connection" means. */
    uint64_t flow_id;
    /* The COORDINATE SPACE: a number per message LIST, on the same counter,
     * so a flow_id and a list_id are never the same number.
     *
     * TWO RECORDS' ANCHORS ARE COMPARABLE EXACTLY WHEN THIS MATCHES, and that
     * is the whole of what the field is for. A flow can carry several lists at
     * once, and the QUIC-stream ones are byte offsets that each start at zero
     * -- so grouping by (flow_id, origin) would put two streams' byte 0 in one
     * space and read two distinct messages as one. `origin` cannot express the
     * difference, because a stream's identity is a number the wire chose.
     *
     * It also moves when a list is REPLACED: a flow evicted and reopened under
     * the same 5-tuple restarts its offsets, so it gets a new id rather than
     * inheriting coordinates that no longer mean anything. */
    uint64_t list_id;
    /* Where the message sits. Read it according to `anchor_space`: a packet
     * INDEX (which is your own push ordinal, counting from zero) or a byte
     * offset within one direction of this list's stream. Comparable only
     * against a record carrying the same `list_id`. */
    uint64_t anchor;
    /* The length the framing unit DECLARED, in bytes. */
    uint64_t unit_len;
    /* Which message of its framing unit this is, from zero. A batch puts
     * several messages at one anchor and this is what keeps them apart. */
    uint32_t batch_index;
    /* Byte offset of this message within its framing unit. */
    uint32_t unit_offset;
    /* 0 = direction A, the half that travels from the flow's lower endpoint to
     * its higher one; 1 = B, the other half. Not a role: the initiator's half
     * is A or B according to which end sorts lower. See "WHICH HALF IS `a`". */
    uint8_t direction;
    /* WZ_DISSECT_ANCHOR_*. */
    uint8_t anchor_space;
    /* WZ_DISSECT_ORIGIN_*. */
    uint8_t origin;
    /* WZ_DISSECT_KIND_*. */
    uint8_t kind;
    /* WZ_DISSECT_FLAG_* bits, or zero. */
    uint32_t flags;
} wz_dissect_record;

/* Open a live dissection. `limits` is WZ_DISSECT_LIMITS_LIVE_TAP for a link,
 * or WZ_DISSECT_LIMITS_NONE for a bounded replay you want nothing discarded
 * from. An unknown value is WZ_DISSECT_ERR_INVALID_ARG and never a quiet
 * fall back to unbounded: on a door whose input does not end, a caller that
 * believes it asked for a ceiling must not be given none.
 *
 * On WZ_DISSECT_OK, `*out` is a handle to be released exactly once with
 * wz_dissect_live_close.
 *
 * @bound limits work-ceiling -- it bounds what the handle RETAINS between
 * packets, and wz_dissect_live_lost is what it discarded. */
int wz_dissect_live_open(int limits, wz_dissect_live **out);

/* Feed one captured packet. `link_type` is its pcap link type -- the same
 * numbering wz_dissect_readable_surfaces reports.
 *
 * `ts_ns` is when the packet was captured, in nanoseconds since the epoch of
 * your clock, or WZ_DISSECT_NO_TIMESTAMP. Every digit is kept: it comes back on
 * the records the packet's messages produce, unrounded (see the record's own
 * field). Pass the instant the packet was captured at and not the instant you
 * call this, since a message waiting behind a hole is timed by the packet that
 * carried its first byte, long after you pushed it.
 *
 * A packet on a link this build does not decode is COUNTED as skipped and
 * returns WZ_DISSECT_OK. A tap sees whatever the interface gives it, and a
 * call that failed per packet would make an ordinary mixed capture look
 * like a broken consumer -- which teaches a consumer to ignore the return
 * value, and that is worse than not having one. */
int wz_dissect_live_push(wz_dissect_live *h, unsigned int link_type,
                         uint64_t ts_ns, const unsigned char *bytes,
                         size_t len);

/* ── R2373 (ABI 15) — A CONTAINER THAT IS STILL BEING WRITTEN ────────────
 *
 * Feed a GROWING capture container into an existing handle.
 *
 * wz_dissect_pcap_replay below takes a container and OPENS a handle; this
 * takes a container and CONTINUES one. Between them they had a hole exactly
 * the shape of a capture backend that is still writing -- a privileged helper
 * appending to a pcapng and a reader mapping the same file up to a cursor the
 * helper publishes after each complete block. That reader has bytes, they are
 * a container, and nothing here would take them without also making a new
 * handle.
 *
 * The handle remembers how far into the container it has parsed. Hand it the
 * whole prefix you have -- a growing mmap gives you exactly that, at no copy
 * -- and it consumes only the blocks that became complete since the last
 * call. Coordinates, session context, the decryption-secret budget and the
 * lost count all CONTINUE, exactly as they do across the
 * wz_dissect_pcap_replay -> wz_dissect_live_push seam.
 *
 *     wz_dissect_live *h;
 *     wz_dissect_live_open(WZ_DISSECT_LIMITS_LIVE_TAP, &h);
 *     for (;;) {
 *         size_t upto = published_cursor();     // your writer's own figure
 *         if (wz_dissect_live_follow(h, mapped, upto)) { ... }
 *         wz_dissect_record buf[256]; size_t n;
 *         while (!wz_dissect_live_drain(h, buf, 256, &n) && n) { ... }
 *     }
 *
 * WHY THE WHOLE PREFIX RATHER THAN THE NEW BYTES. A suffix of a pcapng is not
 * a container: no Section Header, no Interface Description. Handing over
 * [known, cursor) would mean splicing a header onto it, and a consumer that
 * writes pcapng headers is a second WRITER as surely as one that parses them
 * is a second reader.
 *
 * WHY NOT CALL wz_dissect_pcap_replay ON THE PREFIX EACH WINDOW. It fails on
 * CORRECTNESS, not on speed. Each such call builds a NEW handle, so
 * wz_dissect_live_lost restarts at zero -- and that counter is the only thing
 * separating "the link went quiet" from "this reader could not keep up", so a
 * consumer resetting it every window reports a floor as a total, permanently.
 * Packet coordinates restart with it, which is the very thing the replay ->
 * push seam is documented to avoid. The quadratic cost is real and it is the
 * SECOND problem.
 *
 * A PREFIX ENDING MID-BLOCK IS LEGAL. It consumes nothing extra, and the next
 * call with more bytes decodes that block. A door that worked only on
 * block-aligned prefixes would hand the alignment rule back to you, which is
 * format knowledge outside this library again.
 *
 * IT DOES NOT FINISH THE DISSECTION. A container still being written has no
 * last packet, so the gap patience a file's end makes final is left unspent.
 * That is the one behaviour separating this from wz_dissect_pcap_replay over
 * the same bytes.
 *
 * EITHER FORMAT, chosen by the container's magic once, exactly as the replay
 * door chooses it.
 *
 * `len` is how much of the container is READABLE AND COMMITTED right now, and
 * it is an input length rather than a bound of any kind: this library reads no
 * byte past it, imposes no ceiling by it, and discards nothing for it. What
 * the handle RETAINS is still the preset wz_dissect_live_open was given, and
 * wz_dissect_live_lost is still what that discarded.
 *
 * WZ_DISSECT_ERR_BAD_CAPTURE for a container that does not read.
 * WZ_DISSECT_ERR_CONTAINER_SHRANK when `len` is below what this handle has
 * already consumed. */
int wz_dissect_live_follow(wz_dissect_live *h, const unsigned char *bytes,
                           size_t len);

/* Take the messages decoded since the last drain into `out`, which holds
 * `cap` records; `*written` receives how many were filled.
 *
 * If more are ready than `cap` holds, the rest stay, in order -- drain in a
 * loop until you get a short count. A `cap` of zero writes nothing and is
 * legal: it is how you ask the handle to bring its own accounting up to
 * date without taking anything.
 *
 * ORDER: records are grouped by the flow-list they came from, each list in
 * the order it decoded them. They are NOT globally sorted by time. Sort on
 * `ts_ns` if you need that -- a live reader cannot do it for you without
 * holding messages back until nothing older can arrive, and on a link that
 * moment never comes.
 *
 * WHAT EQUAL `ts_ns` MEANS, AND THE TIEBREAK. `ts_ns` is the capture instant of
 * the packet that carried the message's first byte and keeps the nanosecond, so
 * two messages share one only when they share a packet or when a source stamped
 * two packets alike (a coarse clock). Use a STABLE sort, and the order of equal
 * values is this:
 *
 *   - within one list_id, the order the list decoded them in. For two
 *     messages of one packet that is the byte order of the packet, and for a
 *     datagram list `(anchor, batch_index)` is that order and is comparable
 *     (a datagram's anchor is its packet index);
 *   - between lists, the order they were drained in, which is deterministic for
 *     a given handle and call pattern but is NOT capture order: a capture
 *     drained in steps of one packet and the same capture drained once may place
 *     equal-`ts_ns` messages of different lists differently, and no order is
 *     claimed between them.
 *
 * A message that completes after one that began later (a unit spanning packets)
 * is listed after it but carries the earlier `ts_ns`, so a list's `ts_ns` is not
 * monotone along it, and the sort is what puts it right. The order that is
 * CAPTURE order for every row, ties included, is the field document's: a
 * stream flow's rows come out by the packet of each row's first byte and then
 * their place in it, and a row and a record join on `(list_id, direction,
 * anchor, batch_index)`.
 *
 * @bound cap buffer-capacity -- it is the size of YOUR array. This library
 * imposes nothing by it and discards nothing for it: what does not fit
 * stays, and `*written` says what did. */
int wz_dissect_live_drain(wz_dissect_live *h, wz_dissect_record *out,
                          size_t cap, size_t *written);

/* Messages this handle decoded and then DISCARDED before you drained them,
 * cumulative: a ceiling trimming a flow's list, or a flow evicted to stay
 * inside the flow cap.
 *
 * Read it when you RENDER, not once per drain, which is why it is its own
 * door rather than another out-parameter. Non-zero is the one thing that
 * separates "the link went quiet" from "this reader could not keep up", and
 * a bounded read that could not say so would be reporting a floor as a
 * total. `0` for a null handle. */
uint64_t wz_dissect_live_lost(const wz_dissect_live *h);

/* ── R2205 (ABI 14) — THE BYTES UNDER THE DESCRIPTION ────────────────────
 *
 * Every other output of this library DESCRIBES what was decoded: a document
 * naming the fields, or a record saying that a message arrived, when, on which
 * flow. A consumer rendering the message ITSELF -- a hex view with the field
 * the reader picked lit up inside it -- needs the bytes under that
 * description, and until this door existed no symbol here handed any back.
 * Measured before it was written: of the entry points this file declares, ZERO
 * took an `unsigned char *` out parameter or returned one.
 *
 * HALF OF THAT GAP WAS NEVER OURS, and this door says which half by name. A
 * record whose `anchor_space` is WZ_DISSECT_ANCHOR_PACKET names a packet YOU
 * pushed, and `unit_offset` says where inside it the message stands -- so
 * those bytes are already in your hands, and asking for them here is
 * WZ_DISSECT_ERR_NO_BYTE_SOURCE rather than a copy of what you are holding.
 * The half that was ours is WZ_DISSECT_ANCHOR_STREAM_BYTES: that coordinate is
 * an offset into a stream THIS READER reassembled out of many packets, and a
 * consumer has no such stream to index.
 *
 * WHY IT TAKES THE RECORD AND NOT A SPAN. The obvious door is
 * `(list_id, direction, start, end)`, and it cannot be written: finding a
 * message inside its framing unit needs the width of the length prefix, and no
 * coordinate this ABI publishes carries it -- `anchor` names the PREFIX, not
 * the body behind it. A span door would therefore hand every consumer the job
 * of re-deriving this library's framing rule out of numbers that cannot
 * express it, which is the second decoder this whole ABI exists to avoid.
 * Passing the record back costs you nothing -- it is the value you just
 * drained -- and it makes an unanswerable question unaskable: there is no way
 * to name a range that is not a message.
 *
 * WHAT COMES BACK is the slice the field walker itself was handed: from the
 * message's first byte to the end of the framing unit it arrived in. Byte 0 is
 * the message's byte 0, so a span out of the `fields` document -- which is
 * message-relative -- indexes this buffer directly, with no arithmetic in
 * between. A unit carrying a BATCH runs on past this message; what bounds it is
 * the next record sharing this one's `list_id`, `direction` and `anchor`, whose
 * `unit_offset` is where this message stops. That trailing region is
 * deliberately not trimmed away -- the difference between what the walk covered
 * and what the wire carried is the one thing a hex view is for.
 *
 * SIZING, and it never truncates. `needed` always receives the message's full
 * length. When `cap` is at least that, `out` holds the bytes; when it is less,
 * NOTHING is written -- size and call again. You know your own `cap`, so
 * `cap >= *needed` IS the answer to "did it write", and there is nothing
 * ambiguous to tell apart. `out` may be null when `cap` is zero, which is how
 * you ask for the length alone.
 *
 *     size_t n;
 *     if (wz_dissect_live_message_bytes(h, &rec, NULL, 0, &n) == WZ_DISSECT_OK) {
 *         unsigned char *buf = malloc(n);
 *         wz_dissect_live_message_bytes(h, &rec, buf, n, &n);
 *         ...                          // render buf[0..n]
 *         free(buf);                   // YOURS. Nothing here to give back.
 *     }
 *
 * READ THE MEMORY RULE AT THE TOP OF THIS FILE. This door adds nothing to it:
 * the bytes go into a buffer you own, so there is no new thing to release and
 * no callback. The R2205 paragraph there says so in the rule's own words.
 *
 * The record must be one THIS handle drained. A record from another handle
 * names coordinates in another handle's spaces and is answered
 * WZ_DISSECT_ERR_BYTES_RETIRED -- a miss, never another message's bytes.
 *
 * A MESSAGE READ OUT OF AN LZ4 BATCH. On a session that negotiated
 * compression the batch is lz4 on the wire and its messages exist only once
 * this reader has opened it. For such a message this door answers the
 * MESSAGE's own bytes, exactly -- not the rest of a unit, which was never on
 * the wire in that form -- and they are still what the field walker was handed.
 * Its field row's `first_byte` is `null`, because no packet byte holds it.
 *
 * @bound cap buffer-capacity -- the size of YOUR array. This library imposes
 * nothing by it and discards nothing for it: below the length it writes
 * nothing at all, and `needed` says how much there is. */
int wz_dissect_live_message_bytes(const wz_dissect_live *h,
                                  const wz_dissect_record *record,
                                  unsigned char *out, size_t cap,
                                  size_t *needed);

/* ── (ABI 19) — THE JOINED BUFFER OF A COMPLETED FRAGMENT CHAIN ──
 *
 * A field row whose above_transport.carried_state is `reassembled` carries
 * above_transport.fields and above_transport.carried, and their start/end
 * index the buffer the chain was JOINED in -- which never crossed the wire in
 * one piece, and which no other door hands out. This one does, so those spans
 * can be drawn on the bytes they describe.
 *
 * WHICH ROW: the record, the same wz_dissect_record wz_dissect_live_drain
 * wrote and a live field row carries (list_id, direction, anchor,
 * batch_index), resolved exactly as wz_dissect_live_message_bytes resolves it.
 * Not `chain_id`: that is an identity the FIELD DOCUMENT assigns as it renders,
 * and this library keeps no table from it back to a message; and it names a
 * whole chain, when the buffer belongs to the one row that completed it. Find
 * that row by its `chain.outcome` of `reassembled` and pass its record.
 *
 * NOT wz_dissect_live_message_bytes WITH A FLAG. Both take the same record and
 * answer DIFFERENT bytes of it: that door the bytes the row's own `fields` were
 * walked from -- for a completing Fragment, the fragment as it crossed the
 * wire, or NO_BYTE_SOURCE on a datagram link, where that is the packet you
 * pushed -- and this one the buffer under `above_transport`. Two doors keep one
 * record from meaning two ranges depending on an argument.
 *
 * OWNERSHIP, and it is the rule of the door above, unchanged. The buffer is
 * COPIED into memory you own and sized; `needed` always receives its full
 * length, and below it NOTHING is written -- size and call again. A borrowed
 * view into the handle was weighed and refused: the handle trims and evicts as
 * it is fed, so such a pointer would be valid only "until the next push", a
 * lifetime nothing on your side can check, and this ABI has never handed out a
 * pointer into its own memory that you do not free yourself.
 *
 *     size_t n;
 *     if (wz_dissect_live_reassembled_bytes(h, &rec, NULL, 0, &n) == WZ_DISSECT_OK) {
 *         unsigned char *buf = malloc(n);
 *         wz_dissect_live_reassembled_bytes(h, &rec, buf, n, &n);
 *         ...           // draw above_transport.fields spans over buf[0..n]
 *         free(buf);
 *     }
 *
 * ANSWERS. WZ_DISSECT_OK with the length; WZ_DISSECT_ERR_NOT_REASSEMBLED for a
 * record whose message did not complete a chain (every scouting record, every
 * row whose carried_state is not `reassembled`) -- per RECORD, so the next one
 * may answer, and asking again for this one never will;
 * WZ_DISSECT_ERR_BYTES_RETIRED for a record this handle no longer holds.
 * `needed` is zero on both failures.
 *
 * ⚠ THESE ARE NOT CAPTURE BYTES. Offsets into this buffer are offsets into the
 * reader's own join, never into a packet; do not add them to a row's
 * `first_byte` or `message_at`.
 *
 * @bound cap buffer-capacity -- the size of YOUR array. This library imposes
 * nothing by it and discards nothing for it: below the length it writes
 * nothing at all, and `needed` says how much there is. */
int wz_dissect_live_reassembled_bytes(const wz_dissect_live *h,
                                      const wz_dissect_record *record,
                                      unsigned char *out, size_t cap,
                                      size_t *needed);

/* ── (ABI 21) — THE CAPTURED FRAME OF A PACKET ──────────────────
 *
 * A field row's `first_byte` names `packet` -- the captured packet holding the
 * row's first byte -- and `frame_offset`, where that byte sits in the CAPTURED
 * FRAME with its link header. This door hands out that frame, so the offset
 * can be drawn on the bytes it indexes. No other door did:
 * wz_dissect_live_message_bytes answers the message's own bytes and
 * wz_dissect_live_reassembled_bytes the buffer a fragment chain was joined in,
 * and neither is the frame the capture stored.
 *
 * WHICH CONTAINER: `bytes` and `len` are the capture container itself -- the
 * same prefix you feed wz_dissect_live_follow, or a longer one. Not a handle:
 * this library keeps no captured frame. A handle holds the decapsulated
 * payloads its messages were read from and trims them under its ceilings, so a
 * door keyed by one would have to start retaining every packet, or answer
 * BYTES_RETIRED for the old ones, which for a large capture is most of them.
 * You hold the container; this reads what you already have.
 *
 * THE SAME READER THAT NUMBERS THE PACKETS. The walk is the one
 * wz_dissect_live_follow runs, so `packet` is the same number by construction
 * and no record header is parsed a second time. Decoding the container
 * yourself to reach a packet would be the second decoder of the capture
 * framing that this header forbids by name.
 *
 * GROWTH. A packet number is a position in a file and a file only grows: a
 * number that one prefix resolves resolves to the same bytes in every longer
 * one. A prefix that does NOT hold the record whole answers NO_SUCH_PACKET --
 * the honest answer, and not a corruption.
 *
 * COST, said plainly. The walk stops at the packet, so a call reads the header
 * of every record before it and copies none of them: linear in the packet's
 * number. That is the price of asking a container, rather than an index built
 * by somebody who read it first, for a packet by number. Keep the frames you
 * have already been handed if you ask for many packets of one large container.
 *
 * OWNERSHIP, and it is the rule of wz_dissect_live_message_bytes, unchanged.
 * The frame is COPIED into memory you own and sized; `needed` always receives
 * its full length, and below it NOTHING is written -- size and call again.
 *
 *     size_t n;
 *     if (wz_dissect_pcap_frame_bytes(file, file_len, pkt, NULL, 0, &n)
 *             == WZ_DISSECT_OK) {
 *         unsigned char *buf = malloc(n);
 *         wz_dissect_pcap_frame_bytes(file, file_len, pkt, buf, n, &n);
 *         ...           // highlight buf[frame_offset], link header included
 *         free(buf);
 *     }
 *
 * ANSWERS. WZ_DISSECT_OK with the length; WZ_DISSECT_ERR_NO_SUCH_PACKET when
 * `bytes` holds no packet with that number; WZ_DISSECT_ERR_BAD_CAPTURE when
 * the container does not read before the walk reaches the packet;
 * WZ_DISSECT_ERR_INVALID_ARG for a null pointer. `needed` is zero on every
 * failure. `out` must not overlap `bytes`.
 *
 * @bound cap buffer-capacity -- the size of YOUR array. This library imposes
 * nothing by it and discards nothing for it: below the length it writes
 * nothing at all, and `needed` says how much there is. */
int wz_dissect_pcap_frame_bytes(const unsigned char *bytes, size_t len,
                                uint64_t packet, unsigned char *out,
                                size_t cap, size_t *needed);

/* ── R2453 (ABI 16) — THE ANALYSIS PLANES OVER A LIVE HANDLE ─────────────
 *
 * The census doors above take a capture CONTAINER, and until this revision not
 * one of them took a wz_dissect_live *. So the five planes -- exchanges,
 * interests, keyexprs, nodes, payloads -- were reachable only by handing a
 * whole file in, and a consumer watching a RUNNING link could learn that a
 * message arrived and could not learn which key carried it, who declared it,
 * or whether a query was answered.
 *
 * wz_dissect_live_follow crossed this seam in the other direction: bytes into
 * an open handle. This is the aggregate coming back out, and the pair is what
 * removes the two workarounds a consumer is otherwise left with. Both are
 * refusals this header already makes elsewhere. Re-feeding a growing prefix to
 * a container door means a NEW dissection each window, so wz_dissect_live_lost
 * returns to zero and the census's own cumulative counts -- records,
 * declarations, total_payload_bytes, the gap group, dropped_by_limits -- can no
 * longer be told from a restart. Aggregating the drained records by hand means
 * a second counter of facts this library already counts, which does not fail:
 * it diverges.
 *
 * ONE door here answers what FOUR answer over a container. That family varies
 * two axes -- selector and limit preset -- and names all four combinations.
 * Over a handle the LIMIT axis is not an argument: it was chosen at
 * wz_dissect_live_open and is a property of the handle, so taking it again
 * here would be the same fact in two places, and the two would part the first
 * time a caller passed the other one. What is left is the selector, and an
 * EMPTY selector is the identity, so:
 *
 *   open(NONE)     + census("")    is wz_dissect_pcap_census
 *   open(LIVE_TAP) + census("")    is wz_dissect_pcap_census_bounded
 *   open(NONE)     + census(expr)  is wz_dissect_pcap_census_where
 *   open(LIVE_TAP) + census(expr)  is wz_dissect_pcap_census_where_limited
 *
 * It is a READ, and `h` is const to say so. Drawing a window must not change
 * what the tap decodes; the one act that would is wz_dissect_live_end below.
 *
 * The document is the one the census doors emit, so a consumer keeps one
 * reader and one schema across both halves. A selector that does not compile
 * returns WZ_DISSECT_ERR_SELECTOR and no string; for the position, call
 * wz_dissect_selector_diagnose. */
int wz_dissect_live_census(const wz_dissect_live *h, const char *selector,
                           char **out);

/* R2453 (ABI 16) — THE FEED ENDED: spend the patience a capture's last packet
 * spends.
 *
 * A file ends, so every door taking (bytes, len) gives up on a reassembly gap
 * that never filled, and the bytes BEHIND that gap decode as a discontinuity.
 * A tap does not end, so a handle never reaches that moment on its own.
 *
 * MEASURED on a capture whose last act is an unfilled gap: the census of the
 * same bytes reports 32 walked records before this call and 94 after it.
 * Without this, a consumer replaying a finite capture through the live doors
 * reads a SHORT document and cannot reach the answer the container doors give
 * for those very bytes -- which is the property this pair is judged by.
 *
 * It does NOT close the handle and feeding may continue: wz_dissect_pcap_replay
 * has ended its feed since R2373 and still hands back a followable handle.
 * "Ended" means the patience is spent, not that the handle is done. What that
 * costs is a gap a late retransmission would have filled being already a
 * discontinuity -- the same trade a file's end makes, made when you say so.
 *
 * Returns nothing and null is a no-op: nothing here can fail, and an error
 * channel with no error in it is one a caller learns to ignore. Releasing the
 * handle is still wz_dissect_live_close's job. */
void wz_dissect_live_end(wz_dissect_live *h);

/* (ABI 18) -- THE FIELD DOCUMENT OVER A LIVE HANDLE, each row
 * carrying the record coordinates of that handle.
 *
 * R2453 gave the census a live door so its planes and the drained records
 * describe ONE dissection. The field document had none: rows came from
 * wz_dissect_pcap_fields_where_limited, a second dissection of the same file,
 * and a consumer joined them to records by direction and anchor order -- which
 * holds on a capture with one flow and on nothing else. With several flows, or
 * datagram rows, a row's detail had no published key to reach its record by.
 *
 * This renders the same document over the HANDLE's dissection (field-document
 * revision 15), and every row gains
 *
 *     "list_id":L,"anchor":A,"batch_index":B
 *
 * with the meanings wz_dissect_record gives them. A record and its row join on
 * equal (list_id, direction, anchor, batch_index): stream rows, datagram rows,
 * and the scouting rows whose records carry WZ_DISSECT_ORIGIN_SCOUTING. On a
 * stream row `anchor` is NOT `message_at`: the record's anchor names the
 * framing unit's length prefix, `message_at` the message's first byte.
 *
 * `max_messages_shown_per_flow`, `selector` and `declarations` are exactly
 * wz_dissect_pcap_fields_where_limited's, refused the same way. The limit
 * preset is not an argument: it is the handle's, chosen at open.
 *
 * `bytes`/`len` are the capture container the handle was read from -- by
 * wz_dissect_pcap_replay, or the prefix given to wz_dissect_live_follow.
 * Datagram rows are walked from a second read of their packets, because this
 * reader keeps no copy of a pushed packet, and that read needs the container.
 * A handle fed by wz_dissect_live_push has none: pass NULL, 0 and the document
 * renders no datagram rows and says so with "capture_reread":false.
 *
 * `bytes` may END ANYWHERE. Since field-document revision 21 a prefix cut
 * inside a record is read up to its last whole record, by the walk
 * wz_dissect_pcap_frame_bytes answers a packet by number with, so every packet
 * the handle has decoded is there and a row carries the same `frame_offset` and
 * `l2` it carries once the record is whole: the document over such a prefix is
 * the document over the boundary before it. "capture_reread":false therefore
 * means the bytes are not a capture container -- shorter than its file header,
 * or malformed -- and no longer means a record was cut off.
 *
 * `h` is not const. A list not drained yet has no id, so the ids are settled
 * first by the reconciliation a drain performs, handing out no record: the next
 * wz_dissect_live_drain returns exactly what it would have, under the same ids.
 * Nothing decoded changes; wz_dissect_live_end is still the only act that
 * would.
 *
 * Since field-document revision 19 each row also carries `"seq":N`, the number
 * wz_dissect_live_fields_since takes as its cursor; see there.
 *
 * @bound max_messages_shown_per_flow trims-output -- the DOCUMENT is
 * shortened after the walk; `shown`/`omitted` report it. */
int wz_dissect_live_fields_where(wz_dissect_live *h,
                                 const unsigned char *bytes, size_t len,
                                 size_t max_messages_shown_per_flow,
                                 const char *selector,
                                 const char *declarations, char **out);

/* (ABI 22) -- THE ROWS OF THAT DOCUMENT AFTER A CURSOR, and only those.
 *
 * wz_dissect_live_fields_where renders every row the handle holds, every time,
 * at about 2.3 KB a row. A list that refreshed once per feed step therefore
 * received and parsed each row again at every step. This door writes the rows
 * whose `seq` is greater than `after_seq`; the cost of an answer follows what is
 * new.
 *
 * THE CURSOR. Since field-document revision 19 every row a live door writes
 * carries `"seq":N`: the handle's count of rows it has issued, in the order it
 * first issued them. It is unique and increasing, and a ceiling trimming a list
 * or a flow being replaced does not change it -- which the position of a row in
 * the document does not promise, because rows come out grouped by flow and a
 * row's place moves when another flow grows. It is NOT part of the join: a row
 * and a drained record still meet on (list_id, direction, anchor, batch_index).
 * Numbers are not dense; a message a ceiling took before the handle looked was
 * never issued and takes none. 0 asks for every row. Rows the handle sees for
 * the first time in ONE call are numbered in the order it holds its lists, not
 * in capture order; a caller that feeds and asks in steps gets them in the order
 * they arrived, which is the order a live consumer runs in.
 *
 * The document is the one above with the rows before the cursor left out, and
 * gains a top-level
 *
 *     "window":{"after_seq":A,"through_seq":T}
 *
 * `after_seq` is the cursor you gave. `through_seq` is the highest number the
 * handle had issued when the document was made, and is the cursor to give next.
 * It is not the highest row written: a datagram row whose second read was
 * declined has a number and no row, now or later, and is listed under
 * `disagreements`; the cursor passes it. A cursor above `through_seq` is not an
 * error and gets no rows.
 *
 * WHAT IT DOES NOT TAKE. No `selector` and no `max_messages_shown_per_flow`. A
 * selector's verdict is a walk over the whole capture and would put back the
 * cost this door removes -- wz_dissect_live_selection is the door for narrowing.
 * A cap counts rows from the front of a list, which a cursor turns into a
 * different question. `bytes`/`len` and `declarations` are that door's, refused
 * the same way.
 *
 * WHAT ELSE DIFFERS. Every flow object is written, with `messages` empty when
 * the flow has nothing new, so the flow's `context` is refreshed on every call.
 * The tallies rows feed -- `disagreements`, `payload_mapping_counts` and
 * `payload_refusals` -- count the rows written in THIS document, and
 * `payload_mapping_counts_exact` is false whenever the cursor passed a row over,
 * which is what that flag means.
 *
 * A ROW THAT WAS WRITTEN DOES NOT CHANGE, EXCEPT THESE CELLS. Rows here are the
 * whole-document door's rows, written by the same function, so a row is byte for
 * byte the row that door writes at the same handle state. Between STATES, a row
 * still held can read differently in exactly these cells, and in no others; a
 * path is the row's keys joined by a slash, "[]" is any element of an array, and
 * a cell named as a whole subtree means every cell beneath it:
 *
 *     /carried[]/keyexpr                       a declaration is stamped with the
 *     /carried[]/keyexpr_cause                 packet it went past at, and one
 *     /above_transport/carried[]/keyexpr       that is DECODED later than a packet
 *     /above_transport/carried[]/keyexpr_cause that followed it -- a TCP segment
 *     /payload_decode (its whole subtree)      that arrived ahead of its
 *                                              predecessor is held until the gap
 *                                              fills -- resolves a reference that
 *                                              was written unresolved. Do not
 *                                              keep these across calls as final.
 *     /carried[]/keyexpr_id                    since revision 24: the id moves with
 *     /above_transport/carried[]/keyexpr_id    the `keyexpr` it was written beside.
 *     /chain/chain_id                         chains are numbered from the first
 *                                              message the list still holds, so
 *                                              a front trim renumbers them. It
 *                                              names a chain within ONE document.
 *
 * Since field-document revision 22 the list also names
 * /above_transport/carried[]/payload_decode, its whole subtree, which starts
 * from the same resolved key as the entry's /keyexpr beside it and so moves in
 * the same states.
 *
 * Since field-document revision 34 it names /carried[]/e2e and
 * /above_transport/carried[]/e2e, each its whole subtree, the key included: the
 * block exists only for a key a rule covers (so it arrives with the key's
 * resolution), and a counter's verdict depends on the frames of its slot before
 * it in the document (so a front trim, or a zid learned late, moves it).
 *
 * A row whose message bytes the per-direction byte ceiling has since discarded
 * reads, if it is asked for again, as `declined` in place of its walk: /name,
 * /fields, /carried, /above_transport, /first_byte, /l2 and /declined swap. The
 * row you hold stays true -- the bytes were the message's when it was written --
 * so do not treat that `declined` as a correction. `seq`, the four coordinates,
 * `direction`, `offset_space`, `message_at`, `packet`, `sn` and the rest of
 * `chain` do not change. A chain result arrives as a NEW row, the one that
 * completed the chain, and never as a change to an earlier fragment's row.
 * wz_dissect_live_end releases held messages as new rows and changes no row
 * already written. The flow object around the rows is not covered.
 *
 * TAKE IT AT THE STATE THE DRAIN WAS TAKEN AT. wz_dissect_live_end releases what
 * a reassembly gap was holding, so a document taken before it and records
 * drained after it disagree by exactly those messages -- the join fails because
 * they are two states, not because a row changed. Call this door and
 * wz_dissect_live_drain on the same side of it.
 *
 * `h` is not const, for the reason wz_dissect_live_fields_where gives: ids and
 * row numbers are settled first by the reconciliation a drain performs, handing
 * out no record. */
int wz_dissect_live_fields_since(wz_dissect_live *h,
                                 const unsigned char *bytes, size_t len,
                                 const char *declarations,
                                 uint64_t after_seq, char **out);

/* (ABI 20) -- THE VERDICT OF A SELECTOR OVER THE ROWS OF THAT
 * DOCUMENT, and nothing beside it.
 *
 * wz_dissect_live_fields_where says which rows a selector picked inside a
 * document that renders every row's whole tree, carried state and session
 * verdicts. A consumer narrowing a message list needs, per row, only the four
 * coordinates that join the row to a record and the word the selector said.
 * Measured by that consumer on a capture of 25,360 rows: 171 ms for the door,
 * 58 MB of document and 1.5 s to read it, on every chip toggle. This door
 * writes those five values per row and the ceilings that made the list short:
 *
 *     {"document":{"name":"selection","revision":R},
 *      "rows":[{"direction":"a","list_id":L,"anchor":A,"batch_index":B,
 *               "selected":"yes"}, ...],
 *      "dropped_by_limits":{...}}
 *
 * It is a document of its own, with its own revision, and not a "no tree" mode
 * of the one above: two shapes behind one name would make every reader of the
 * tree reason about a document that sometimes has none.
 *
 * THE VERDICT IS THE SAME ONE. Each row's word is decided by the same function
 * the field document's is, the coordinates are the same numbers with the same
 * meanings (a record and its row join on equal list_id, direction, anchor and
 * batch_index), and the rows are the field document's rows in its order: a
 * stream flow's rows by the capture time of their first byte, as that document
 * writes them (since selection revision 3; before it, the order the session
 * decoded them in), a flow's scouting rows after its transport rows, stream
 * flows before datagram flows. What
 * `kind == query` (and every other selector) says of a Request, a ResponseFinal,
 * a Push or a Response row, and which rows stay `unjudged`, is written under
 * wz_dissect_pcap_fields_where_limited and holds here word for word. Two
 * differences, and both are that document's limitation and not this one's:
 *
 *   - The field document renders a datagram row only when it can re-read the
 *     packet from the capture container and the second read agrees. This door
 *     needs no packet -- the verdict is decided by the record plane, not by a
 *     re-walk of the bytes -- so it has a row for every frame the dissection
 *     framed and takes no container. A handle fed by wz_dissect_live_push,
 *     which has none, gets datagram verdicts here that the field document
 *     cannot give it.
 *   - Neither renders a recovered QUIC stream or a serial line: those lists
 *     have no row in the field document, and this document is its rows.
 *
 * AN EMPTY SELECTOR IS THE IDENTITY, as it is for every other door here: it
 * asks nothing, so each row carries its coordinates and no "selected" key. The
 * one thing this door could have done differently -- read an empty selector as
 * "everything matches" and answered "yes" throughout -- would have made it the
 * only door where no selector and the selector that matches all differ.
 * Whitespace is the same selector as nothing. A row of a list you did not
 * number carries no coordinate keys, and never an invented one.
 *
 * `selector` is the language wz_dissect_pcap_census_where_limited takes, and it
 * is refused the same way -- WZ_DISSECT_ERR_SELECTOR, with
 * wz_dissect_selector_diagnose available to say where. There is no `declarations`
 * argument, because the verdict does not depend on how a payload is decoded,
 * and no `max_messages_shown_per_flow`, which trims trees this document does
 * not render. The limit preset is the handle's, chosen at open; a row the walk
 * never reached is ABSENT rather than unmatched, and dropped_by_limits says so.
 *
 * UNDER A `zid` PREFIX THAT IS AMBIGUOUS in what this handle holds (see THE
 * SELECTOR LANGUAGE) every row reads `unjudged` and the document carries
 * `ambiguous_zid_prefixes` beside `rows`, from selection revision 4: which
 * term, the prefix, and the zids it begins. The key is absent when the
 * selector was judged, and the judgement is of the capture as it stands: ask
 * again after the handle has read more.
 *
 * `h` is not const, for the reason wz_dissect_live_fields_where gives: a list
 * not drained yet has no id, so the ids are settled first by the reconciliation
 * a drain performs, handing out no record. The next wz_dissect_live_drain
 * returns exactly what it would have, under the same ids.
 *
 * @values selection direction
 * @values selection selected
 * @carries selection direction passenger
 * @carries selection selected passenger */
int wz_dissect_live_selection(wz_dissect_live *h, const char *selector,
                              char **out);

/* ── (ABI 23) — WHAT AN OPEN HANDLE STILL HOLDS ──────────────────────────
 *
 * Every ceiling a consumer could read (dropped_by_limits.caps) says how much
 * this reader MAY keep, and every counter beside it says how much it has
 * already discarded. Nothing said what it holds NOW, so a viewer captioning
 * "the last N messages; older ones are gone" had to count the rows of a
 * document it had rendered for another purpose. This door writes that:
 *
 *     {"document":{"name":"retention","revision":R},
 *      "held":{"frames":F,"scouting":S,"serial_frames":L,"skipped":K,
 *              "stream_bytes":B,"stream_flows":N,"datagram_flows":M,
 *              "fullest_window":{"messages":W,"stream_bytes":X},
 *              "oldest_ts_ns":T},
 *      "dropped_by_limits":{...}}
 *
 * T is nanoseconds since 1970, about 1.7e18 on a real clock: past 2^53, so from
 * revision 2 it is a STRING of digits there and a bare number only while it is
 * at most 9007199254740991; `null` still means no clock. See the integer rule
 * under the field document.
 *
 * THERE IS NO SINGLE WINDOW, and the document says so rather than summing
 * scopes that share no ceiling. frames_per_flow bounds each flow's decoded
 * messages; on a DATAGRAM flow one budget is shared by its cleartext list, its
 * scouting list and its recovered QUIC datagram list, and each QUIC stream is
 * bounded apart. stream_bytes_per_direction bounds each direction of each TCP
 * flow. max_flows_per_table bounds each of the two flow tables. So for the
 * axes where the scope matters the document gives the TOTAL a caption wants
 * and the FULLEST scope, which is the only figure comparable to a ceiling:
 * held.fullest_window.messages against dropped_by_limits.caps.frames_per_flow,
 * held.fullest_window.stream_bytes against caps.stream_bytes_per_direction,
 * held.stream_flows and held.datagram_flows against caps.max_flows_per_table.
 * Forty thousand messages under a per-flow cap of ten thousand is four busy
 * flows and healthy; the same forty thousand in one flow is a bug, and only the
 * fullest scope tells them apart. A null cap means no ceiling exists.
 *
 * WHAT THE COUNTS ARE.
 *   - held.frames is decoded transport messages RETAINED, whether or not a
 *     wz_dissect_live_drain has handed their records out: a drain reads the
 *     lists and removes nothing. It is not the number of records still to
 *     drain, and it is not a byte count. held.scouting is the same for
 *     scouting datagrams, which a drain also hands out one record each.
 *   - held.stream_bytes is the reassembled bytes RETAINED, over both directions
 *     of every TCP flow. It is the one place this library holds bytes; a
 *     datagram flow holds decoded messages only and no byte figure is invented
 *     for it. It is not the count of bytes ever reassembled, which a trim does
 *     not lower.
 *   - held.serial_frames is the part of held.frames that is a serial line. No
 *     ceiling bounds it, so it is left out of fullest_window: a caption that
 *     sees frames far above fullest_window.messages has a serial line to thank.
 *   - held.skipped is the skipped-packet list, against caps.skipped_packets.
 *
 * oldest_ts_ns is the capture instant of the oldest retained message or
 * scouting datagram, in the unit and on the clock a drained record's ts_ns
 * uses, so the two compare directly: the same figure, with every nanosecond
 * the capture recorded (retention revision 3; it was a whole number of
 * milliseconds, widened, before), for the reason wz_dissect_record.ts_ns gives.
 * It is the MINIMUM
 * over everything held and not the head of each list, because a capture merged
 * from two taps can put a later message ahead of an earlier one and "how far
 * back can I read" asks for the earliest instant. It is null when nothing held
 * carries a clock -- a source with no clock, or nothing held yet -- which is a
 * different fact from 0.
 *
 * NOT IN IT: scout_askers. The set that ceiling bounds is private to the
 * scouting observer, so dropped_by_limits carries the askers dropped so far and
 * no figure for the askers held. No coordinates of the oldest record either:
 * the oldest instant can belong to a scouting datagram, which has no row to
 * name, and a coordinate that sometimes exists would be a second shape.
 *
 * A READ, and `h` is const to say so: the lists are counted in place, no record
 * is handed out and no id is settled, so the next wz_dissect_live_drain returns
 * exactly what it would have. The limit preset is the handle's, chosen at open.
 * Null `h` or `out` is WZ_DISSECT_ERR_INVALID_ARG and no string. The string is
 * released by wz_dissect_string_free. */
int wz_dissect_live_retention(const wz_dissect_live *h, char **out);

/* ── (ABI 24) — WHAT AN OPEN HANDLE HAS LOST OR DOUBTED ──────────────────
 *
 * The summary's `health` object (wz_dissect_pcap_summary) counts what the wire
 * did to the capture -- retransmissions, reordering, checksums that did not
 * verify, fragment chains that never finished -- and what this reader's own
 * ceilings and reach cost it. A summary needs the whole capture in one buffer,
 * which a running tap never has, so a consumer watching a link had every one of
 * those counters inside the handle and no door to read them. This door writes:
 *
 *     {"document":{"name":"health","revision":R},
 *      "health":{...},
 *      "flows_seen":{"stream":S,"datagram":D},
 *      "datagram_sequence":{"frames":F,"missing":M,"gaps":G,"duplicates":U,
 *                           "out_of_window":W,"without_resolution":N}}
 *
 * `health` is the summary's `health` object byte for byte, from the same
 * emitter, so the code that reads one reads the other and neither can report a
 * figure the other omits. Read the summary's description of it for the groups
 * and what each counter counts; nothing about them is restated here.
 *
 * `flows_seen` is how many flows each of the two flow tables has held, evicted
 * ones included. It is the denominator of the stream counters inside `health`:
 * streams.retransmits of 0 is a measurement when S is above 0, and when S is 0
 * there was no TCP flow to retransmit on, which nothing else in `health` says.
 * It counts TABLE ENTRIES, not distinct 5-tuples, so a flow that was evicted
 * and then seen again is counted again.
 *
 * IT IS NOT `held.stream_flows + dropped_by_limits.flows`. The retention
 * document's `held.stream_flows` is the flows in the stream table now, and
 * `dropped_by_limits.flows` counts evictions from BOTH tables as one number, so
 * the sum over-reads the stream table on any capture that evicted a datagram
 * flow -- on a capture with no TCP packet at all it is not zero.
 *
 * (health revision 2) `datagram_sequence` is the `sequence` group of `health`
 * over the datagram links alone: the same six counters with the same meaning,
 * so one reader reads both. `health.sequence` is the sum over every link, which
 * puts TCP frames in the denominator of any loss rate taken from it, and the
 * sum cannot be split afterwards. This is the datagram share. It is
 * CUMULATIVE and never decreases: it counts the datagram flows the handle holds
 * and every datagram flow its flow cap has already retired, so a consumer that
 * wants the trailing window reads it twice and subtracts. The stream share is
 * `health.sequence` minus it. `missing` follows the integer rule (a bare number
 * up to 2^53 - 1, the same digits in a string above it). A READ of counters: the
 * cost follows the number of live datagram flows, not the number of rows they
 * hold.
 *
 * (health revision 3) `health.streams` carries `transport_checksum_partial`, and
 * `transport_checksum_invalid` no longer counts a segment whose checksum field
 * is exactly its own folded pseudo-header sum -- what a host's own transmit path
 * shows before its network card finishes the checksum. A live tap on the host's
 * own interface sees those in nearly every segment it sends, which is why this
 * door moved with the summary. The rule, what `partial` does and does not
 * claim, and the rule for `uncorroborated_layers` are the summary's (see
 * wz_dissect_pcap_summary, revision 6) and are the same here: one emitter
 * writes both.
 *
 * A READ, and `h` is const to say so: the counters are read where they sit, no
 * record is handed out and no id is settled, so the next
 * wz_dissect_live_drain returns exactly what it would have. The limit preset is
 * the handle's, chosen at open. Null `h` or `out` is WZ_DISSECT_ERR_INVALID_ARG
 * and no string. The string is released by wz_dissect_string_free. */
int wz_dissect_live_health(const wz_dissect_live *h, char **out);

/* Release a live handle. Null is a no-op, so your cleanup path needs no
 * guard of its own -- the same rule wz_dissect_string_free follows, and the
 * commonest source of a double free at an FFI seam. */
void wz_dissect_live_close(wz_dissect_live *h);

/* ── R2171 (ABI 13) — THE DOOR BETWEEN THE TWO HALVES ────────────────────
 *
 * Read a whole capture FILE and hand back a LIVE HANDLE, so the records above
 * can be taken from a capture that has already been written down.
 *
 * Until this existed the header had two halves and nothing joining them. The
 * pcap doors take a whole file and return a JSON document; the live family
 * takes packets one at a time and fills wz_dissect_record. A FROZEN capture --
 * the one input a regression test can hold still, and what an operator hands
 * over when something went wrong -- could reach the document doors and could
 * not reach the record door at all. A consumer wanting both had to open the
 * container itself and drive wz_dissect_live_push per packet, which puts a
 * SECOND reader of the pcap format in the system; the two then disagree, and
 * the one that disagrees silently is the one outside this library.
 *
 * The paragraph on WZ_DISSECT_LIMITS_NONE at wz_dissect_live_open already
 * described the caller this is for -- "a bounded replay you want nothing
 * discarded from". That sentence had no door to name. This is it.
 *
 *     wz_dissect_live *h;
 *     if (wz_dissect_pcap_replay(bytes, len, WZ_DISSECT_LIMITS_NONE, &h)) {...}
 *     wz_dissect_record buf[256];
 *     size_t n;
 *     while (!wz_dissect_live_drain(h, buf, 256, &n) && n) { ... }
 *     wz_dissect_live_close(h);
 *
 * EITHER FORMAT, chosen by the file's magic, through the same reader every
 * document door here uses -- so a pcapng's per-interface link types, its
 * Decryption Secrets Blocks and its Interface Statistics all reach the
 * dissection exactly as they do for wz_dissect_pcap_summary. That is the whole
 * reason this is a door rather than advice to loop over the packets yourself.
 *
 * The handle is an ORDINARY live handle: release it with
 * wz_dissect_live_close, read what a ceiling took with wz_dissect_live_lost,
 * and keep pushing with wz_dissect_live_push if a live source continues where
 * the file stopped. The packet coordinates CONTINUE across that seam -- a push
 * after an N-packet replay anchors at N -- because a counter that restarted
 * would put a live packet at a file packet's index and a consumer would read
 * two distinct messages as one.
 *
 * On WZ_DISSECT_OK, `*out` is a handle to be released exactly once. A capture
 * that does not parse is WZ_DISSECT_ERR_BAD_CAPTURE and hands back no handle.
 *
 * @bound limits work-ceiling -- it bounds what the dissection RETAINS while
 * the file is read, and wz_dissect_live_lost is what it discarded. */
int wz_dissect_pcap_replay(const unsigned char *bytes, size_t len, int limits,
                           wz_dissect_live **out);

/* R2108 -- the record's layout, AS THE BUILT LIBRARY SEES IT.
 *
 * Fills `out` with, in order: size, align, then the offset of every field of
 * wz_dissect_record in declaration order. Returns how many values that is. A
 * null `out`, or a `cap` below the count, writes nothing and returns the
 * count, so a caller sizes first and reads second.
 *
 * THIS IS NOT A DOOR FOR CONSUMERS. A program that includes this header
 * already has the layout from the compiler; asking the library for it would be
 * asking the same question twice and believing the second answer. It exists so
 * a GATE outside both languages can read the layout out of the artifact and
 * hold it against a pin that sits beside the ABI revision -- because the two
 * pins that used to hold it, a Rust test and a C block, are edited by the same
 * commit that changes the layout, and two pins that move together are one.
 *
 * @bound cap buffer-capacity -- the size of YOUR array. Below the count it
 * writes nothing and still RETURNS the count, so it never truncates. */
size_t wz_dissect_record_layout(size_t *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* WZ_DISSECT_H */
