# Hardware verdict for the Zephyr admin node

This is the grammar a lab uses to say that the admin node runs on a board. A row
of `deploy/zephyr-boards.json` for this app is HARDWARE only when a ledger entry
holds a run that printed every step below that the row names, and
`scripts/lib/zephyr_board_table_gate.py` reads the entry for exactly these step
names. A row names all of them unless its `verdict_steps` says otherwise, as the
onboard port's row does for the steps it was recorded against (HW.0 to HW.7); the
steps for the second interface follow them (HW.8 to HW.25, which that row names as
the range HW.0 to HW.25), and the steps for the transmit pool image and the receive
pool image are at the end of this file (HW.26 to HW.30 and HW.31 to HW.35, which
their rows name alone).

The steps are run by one program, `scripts/lib/admin_node_verdict.py`. Layer Qza
runs it in its `qemu` mode against the emulated node, labelled `Qza`; a lab runs
its `board` mode against the board, and that mode prints each step as the
sentence below, labelled `HW`, one line per step on standard output and nothing
else there. The program's header says how a lab runs it. The record quotes those
lines as the program printed them: a sentence typed from a console is not a
record of a check. The checks are the same code in both modes; the lines differ
in the label, in HW.0, which quotes the board's READY line, and in the address
that HW.4 names.

## What the host runs

Two stock zenoh routers of the pinned version, on a host that has a link to
the board:

- B listens on the host's address on the board's subnet. The node is told to
  dial it, in step HW.2.
- A dials the node's listener (the locator the node prints in HW.0) and carries
  the REST plugin on the loopback address only.

Both are bound to the board's adapter and nothing else, with multicast scouting
off, so that what the node reports is what it reached on the wire and not what a
scout found. Their ids are fixed (A is sixteen `a`, B sixteen `b`) because the
sentences compare them. The program's `board` mode starts both: B with a
listener on the host's address and no other, A with no listener of its own
(it only dials the node) and the REST plugin on 127.0.0.1.

## The steps

Each line is the sentence the lab prints when the step holds, followed by
` - OK`. A step that does not hold is printed with `FAIL` in place of `OK`.
`<...>` is a value the lab reads off the run.

```
HW.0 the node's console says who and where it is: READY <node id> <locator>
HW.1 GET before the write: the node reports A only
HW.2 PUT connect/endpoints: the node dialled B, GET reports A and B
HW.3 GET config names the written list
HW.4 every session names its link src/dst; A reached <the node's locator>
HW.5 status/connect: the write was replaced, B is live and established
HW.6 a group of two is refused, and status/connect says multi_link_group
HW.7 the main stack kept a quarter free: stack: peak <N> of <M> bytes
```

HW.7 passes when `N * 4 <= M * 3`. It is a floor and not a target: a record
that passes with the stack nearly full says so in what it did not settle.

## What the ledger entry holds

The entry a row cites as its record must say, in its text:

- the date, the board and the chip, and the commit the images were built from;
- who ran it, as a role and not as a name;
- for EVERY image the board ran (the app's, and each companion the row
  requires), the sha256 of the image as it was flashed;
- the sentence of every step the row names (the eight above for the onboard port),
  each ending ` - OK`;
- what the run did not settle.

The table row carries the same hash, date and who as keys of its `witness`, and
the gate refuses a hash that does not appear in the entry. A row that requires
companions is HARDWARE only together with them, and they cite the same entry:
what ran was the images together, and one image's record says nothing about the
pair.

## The second interface (10BASE-T1S): steps HW.8 to HW.25

HW.0 to HW.7 are put to the node's onboard port and were run on the image without
the second interface. The steps below are for the image with both interfaces: the
onboard RMII port and a Microchip LAN8650/1 on a 10BASE-T1S expansion board in the
kit's MikroBUS socket, on one lwIP stack
(`deploy/zephyr-admin-node/overlays/t2g_t1s.conf` plus the lab's values). Nothing
has run on that board or that chip when this is written: every line quoted here
was read out of the firmware source and none was seen on a console.

A row of `deploy/zephyr-boards.json` for the T1S link is HARDWARE only when its
record holds every step of this file, HW.0 to HW.7 included: that image is a
different image from the one HW.0 to HW.7 were first run on, so its onboard port is
graded again, on it (a row that was recorded before these steps existed names the
steps it was recorded against, in its `verdict_steps`). In this image HW.0 to HW.7
are put to the FIRST locator, the onboard port's, and HW.0's line carries a second
locator, which HW.12 reads.

The numbers are step names and not an order. The order to run them in is under
"The images".

### Decisions the lab must state

Nothing in a tracked file says these, and none has a default. The record states each
of them, as values the lab chose, before the first step is printed.

1. How the host reaches the T1S segment, and the peer's address on it: a media
   converter on one of the host's adapters, or a second T1S node with a host behind
   it. HW.16 to HW.21 put two stock routers (C and D, below) on that segment, so
   the peer must be a machine that can run them. A segment whose only other node
   cannot run a router cannot be given those steps, and the row then stays below
   HARDWARE.
2. The values the image was built with: the T1S IPv4 address and netmask, the
   gateway of each interface (HW.14 needs the onboard port to have one), the PLCA
   node id and node count (or PLCA off), whether the T1S station address is given
   or drawn, and whether the image accepts all multicast.
3. Which of the chip's two control lines the expansion board wires to the socket:
   RESET_N to the socket's RST pin, IRQ_N to its INT pin. Each is off in the image
   unless the lab says so. A line that is not wired is named in the record under
   what the run did not settle.
4. The chip the lab expects: a LAN8651 at product revision B1, which is what an
   earlier probe on this lab's expansion board read from DEVID (0x00086512, MODEL
   0x8651, REV 2). A lab with another part states which, and HW.9 is then read against
   that.
5. The peer's place on the PLCA bus: coordinator or follower, its node id, and what
   it can report of its own PLCA state. A peer that reports nothing says so.
6. The SPI rate of the second image, which has to be above 1000000 Hz for HW.22, and
   the instrument that reads SCLK and IRQ_N (an oscilloscope or a logic analyzer)
   with its accuracy. Without such an instrument HW.22 and HW.24 cannot be printed.
7. A capture on the T1S segment (the peer's own interface will do) and one on the
   onboard segment. HW.14 and HW.15 read frames off them.

### What the host runs for these steps

Two more stock routers of the pinned version, on the machine that is on the T1S
segment, bound to that segment's adapter and nothing else, multicast scouting off:

- D listens on the peer's address on the T1S segment. The node is told to dial it,
  in HW.17. Its id is sixteen `d`.
- C dials the node's T1S locator (the second one HW.0 printed) and carries the REST
  plugin on the loopback address only, on a port of its own. Its id is sixteen `c`.

HW.16 to HW.20 are steps 1 to 5 of `scripts/lib/admin_node_verdict.py` (HW.1 to
HW.5) with C in A's place, D in B's, and the node's T1S locator in the place of the
one the emulator lane names. They are run on a boot at which neither A nor B is
running, so that "C only" is the whole list, and before anything else writes the
node's endpoint list, because HW.20 reads the write counter. The program does not
run them yet: it knows A and B only, and their sentences are not the T1S ones.

### The images

The board runs a launcher on its CM0+ core, as for HW.0 to HW.7. The image of the
app is built from the board's conf and `overlays/t2g_t1s.conf` plus the lab's own
overlay of the values in decision 2, and NEVER with `overlays/t2g_t1s_build_values.conf`,
whose numbers are made up so that a build can complete. The board table's gate refuses
that file in a HARDWARE row; HW.8 refuses it on the console. Up to three images are
built, and the record names each by its sha256 and by the overlays it was built with:

- Image 1: the lab's values, PLCA as the lab states it, the default SPI rate (1000000
  Hz asked). HW.0 to HW.21, HW.23 and HW.24 are run on it.
- Image 2: image 1 with `CONFIG_WZ_T1S_SPI_HZ` raised to the rate of decision 6.
  HW.22 is run on it.
- Image 3: image 1 with `CONFIG_WZ_T1S_PLCA=n`, the peer set to plain CSMA/CD too.
  HW.25 is run on it.

Order: image 1 at HW.0 to HW.7; then a fresh boot of image 1 for HW.8 to HW.13 and
HW.15 (the console is captured from before the reset); a fresh boot for HW.16 to
HW.20; then HW.14, then HW.21; then ten resets for HW.23, and HW.24 on the last of
them; then image 2 for HW.22, then image 3 for HW.25.

The board's console (SCB0) is captured from before the reset to the end of each
boot, and every console line below is read out of that capture, not off a screen.

### Console lines these steps read

Each line is printed by `deploy/zephyr-admin-node/rust/src/lib.rs` or
`deploy/zephyr-admin-node/rust/src/mac_lan865x.rs`, on its own line, with nothing
before it. The pattern is an extended regular expression; a capture line that does
not match a pattern is not that line.

```
onboard station   ^wz: station address ([0-9a-f]{2}(:[0-9a-f]{2}){5}) \((given|drawn at this boot)\)$
T1S station       ^wz: 10BASE-T1S station address ([0-9a-f]{2}(:[0-9a-f]{2}){5}) \((given|drawn at this boot)\)$
control lines     ^wz: t1s: reset line (wired|not wired), interrupt line (wired|not wired)$
SPI clock         ^wz: t1s: SCB3, mode 0, [0-9]+ Hz \(divider [0-9]+, oversample [0-9]+\)$
chip and PLCA     ^wz: t1s: (Lan8650|Lan8651) revision (B0|B1), PLCA (off|coordinator, [0-9]+ node\(s\)|follower [0-9]+, count [0-9]+)$
ready             ^ZEPHYR-WZ-ADMIN READY [0-9a-f]+( udp/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:7447)+$
housekeeping      ^zephyr-admin-node: t1s: reconfigured (true|false), status0 0x[0-9a-f]{2,}, phy status 0x[0-9a-f]{4}$
```

The housekeeping line is printed only when something changed (the chip was reset
and configured again, a status flag was raised, or the PLCA state moved): a status
that stays the same prints nothing, however long it stays. Two other housekeeping
lines exist and are not in the table because a healthy run prints neither:
`zephyr-admin-node: t1s: housekeeping failed, not reported again until it recovers:`
(the SPI exchange itself failed) and `zephyr-admin-node: t1s: housekeeping
recovered after` (it succeeded again). Both are about the SPI bus and not the cable.

A bring-up that fails prints one line beginning `wz: t1s: ` that says why (the
configuration was refused, DEVID names no LAN8650/1, the part is a silicon revision no
document grades, or the bus failed during the bring-up), then a `wz: FAIL - ...` line,
and the node does not start. A capture with any line containing the word FAIL is a
run on which HW.8 does not hold.

What the firmware does NOT print, so that no step reads it from the console: the
state of PLCA itself (the flag that says it changed is printed, not the register
that says what it changed to), a link state of the T1S port (10BASE-T1S has no
negotiation, and the lwIP interface prints nothing when it comes up), the peripheral
clock the SPI divider divides, the level of IRQ_N and the time it took to assert,
and any frame or error counter. The steps that need those read them off the segment
or an instrument, and say so.

### The steps

Each line is the sentence the lab prints when the step holds, followed by ` - OK`,
as for HW.0 to HW.7; `<...>` is a value read off the run, and a step that does not
hold is printed with `FAIL` in place of `OK`. No sentence names another step, and
none contains a full stop followed by a space: the table gate reads a record by
splitting at each step name and ending a sentence at the first such stop.

```
HW.8 the console carried no failure line and no made-up-values line, from reset to the last step
HW.9 the chip identifies as <product> revision <revision>
HW.10 the PLCA setting is the lab's: PLCA <the setting the node printed>
HW.11 PLCA became active: phy status <value> within <S> s of READY, and no fault flag in any t1s line
HW.12 two interfaces on one stack: READY <node id> <onboard locator> <T1S locator>, stations <onboard station> and <T1S station>
HW.13 the node id is the onboard port's: <node id> is <onboard station> read last byte first
HW.14 the default route is the onboard port's: a datagram for <address beyond the gateway> left from <onboard station> and none from <T1S station>
HW.15 both interfaces answer at once: <N> of <N> echo replies from <onboard address> and <N> of <N> from <T1S address> to the peer at <peer T1S address>
HW.16 T1S GET before the write: the node reports C only
HW.17 T1S PUT connect/endpoints: the node dialled D over T1S, GET reports C and D
HW.18 T1S GET config names the written list
HW.19 T1S every session names its link src/dst; C reached <the node's T1S locator>
HW.20 T1S status/connect: the write was replaced, D is live and established
HW.21 the T1S cable pulled for <S> s and put back: the node did not restart, <L> t1s line(s) on the pull and <M> on the return, then <N> of <N> echo replies and a GET over T1S
HW.22 SPI above 1 MHz: SCB3 at <N> Hz, SCLK measured <M> Hz, and the identity and the T1S traffic steps held again on that image
HW.23 the control lines are as the lab stated: reset line <state>, interrupt line <state>, 10 of 10 resets reached the chip identity line
HW.24 IRQ_N: <level> at idle, low <T> us after RESET_N was released, <C> chip-select assertions in <W> s of silence
HW.25 PLCA off: PLCA off, and the identity and the T1S traffic steps held again on that image
```

### How each step is read

HW.8. Over the whole capture of the boot under test, no line contains the text
`FAIL`, and no line starts `wz: FAIL - this image was built with made-up values`.
The second is the line the image prints at the start of the chip's bring-up when it
was built with the made-up-values overlay (`CONFIG_WZ_T1S_BUILD_VALUES_ONLY`), and
the node then runs on; the first covers every other stop (`wz: FAIL - ...`,
`ZEPHYR-WZ-ADMIN FAIL rc=...`). The record also names the overlays the image was
built with, by file name.

HW.9. The chip-and-PLCA line is present exactly once per boot, and its product and
revision are the pair of decision 4 (`Lan8651` and `B1` for MODEL 0x8651, REV 2: the
chip crate's `identify`, `crates/wz-eth-lan865x/src/identity.rs`). The line is
printed after the bring-up succeeded, so its presence also says that the bring-up
ran to the end.

HW.10. On the same line, the text after `PLCA ` is the lab's setting: `coordinator,
N node(s)` for id 0 with count N, `follower I, count N` for id I with count N, `off`
for PLCA off. It equals the id and count of decision 2.

HW.11. At most S seconds after READY (S is 10, which is 100 housekeeping intervals at
the default `CONFIG_WZ_T1S_SERVICE_MS` of 100 ms; with another interval, 100 of
them), the capture holds a housekeeping line with `reconfigured false` whose `phy
status` has bit 0x0800 set. That bit is PSTC, "PLCA status changed", and PLCA
active is "a BEACON is regularly sent or received" (`crates/wz-eth-lan865x/src/regs.rs`).
The first such line after a boot is therefore read as PLCA becoming active, for a
coordinator that sends the beacon and for a follower that hears it; that reading
comes from the register's comments and has not been seen on a chip. The firmware
does not print the register, so a later line says that PLCA moved again and not to
what. The step needs the peer already running when the node boots, with PLCA set as
decision 5 states, because a follower has no beacon to become active on until the
coordinator sends one. And no housekeeping line of the whole boot has any of the
bits 0x0010, 0x0020, 0x0040 in `phy status`: BCNBFTO (the bus cycle is too short
for this follower), UNEXPB (another coordinator's beacon was heard) and RXINTO
(another node transmitted in this node's slot, which can mean two nodes with one
id). The peer's own report of its PLCA state, if it has one (decision
5), is copied into the record; it is not part of the pass.

HW.12. The ready line has exactly two locators. The first is the onboard port's, as
in HW.0 and as the lab built it, and the second is `udp/<T1S IPv4 address of decision
2>:7447`. The two station-address lines of the boot differ. The two networks, address
with netmask as the lab built them, do not overlap (the build refuses an overlap, so
this reads what the lab stated against what the image printed).

HW.13. The node id in the ready line is the onboard station address read from its
last byte to its first, written as one hexadecimal number with no leading zero (the
way zenoh prints an id: `zid_to_zenoh_hex`, `crates/wz-session-core/src/zid_hex.rs`).
For `fa:82:52:cc:fa:0c` that is `cfacc5282fa`. It is NOT derived from the T1S
station address, whichever of the two is drawn at that boot.

HW.14. Needs the onboard port to have a gateway (decision 2): without one there is no
default route to keep, because the first interface that has a gateway takes it
(`deploy/zephyr-admin-node/rust/src/net_lwip.rs`). Through C, PUT `connect/endpoints`
with one endpoint whose address is on neither network and is not the peer's. The node
sends its datagram for it by its default route. On the onboard segment's capture the
datagram appears, with the onboard station address as its source and the gateway's
station address as its destination (the host answers for the gateway's address when
the lab has no gateway); on the T1S segment's capture no frame with the T1S station
address as its source carries it. This step writes the node's endpoint list, which
is why it runs after HW.20.

HW.15. From the host, over its onboard adapter, and from the peer, over the T1S
segment, send at least six echo requests each AT THE SAME TIME, to the node's two
addresses. Every one is answered (N of N, N at least 6, as the onboard run of HW.0
to HW.7 was). The T1S segment's capture shows the node's ARP reply and its echo
replies with the T1S station address as their source: that is a frame from the node
seen on a 10BASE-T1S wire, which no earlier step shows, and it is also what shows the
chip transmitting.

HW.16 to HW.20. As HW.1 to HW.5 with the substitutions above. HW.17's endpoint is
`udp/<peer T1S address>:<D's port>`; the wait for each answer is 60 s, as in the
emulator lane. HW.19's accepted link names the node's T1S locator, `udp/<T1S IPv4>:7447`,
as its source.

HW.21. With C's session open over T1S (after HW.20), disconnect the node's T1S
cable for S seconds, S at least 30 (three times the session lease, which is the
10000 ms of `params` in `rust/src/lib.rs`), and connect it again. Passes when all of
these hold:

- the capture holds no second `ZEPHYR-WZ-ADMIN READY` and no second `core clock` line:
  the node did not restart;
- during the pull the capture holds `zephyr-admin-node: 0 session(s)`, which says that
  the pull did cut the path (if it does not, the step did not test a loss);
- L, the housekeeping lines printed between the pull and the return, and M, those
  printed between the return and the end of the step, are each at most 1, and none
  has `reconfigured true`; the lines are copied into the record whatever their
  number. The housekeeping is paced to report a change and not a repeat, so a pull
  shows as at most one line and the return as at most one. They are not the
  `housekeeping failed` or `housekeeping recovered` lines, which belong to the SPI
  bus: neither appears;
- within 60 s of the return, N of N echo requests from the peer are answered (N at
  least 6), and a GET through a router dialled to the node's T1S locator is answered
  (C is started again if its session did not come back by itself, and the record
  says which it was).

Whether a pull moves the chip's PLCA state at all depends on the node's role on the
bus (a follower loses its beacon, a coordinator keeps sending one), and nothing this
procedure rests on says which; the step records what the lines were and does not
predict them.

HW.22. On image 2 the SPI-clock line reports N Hz with N above 1000000 and not above
the rate asked (the block rounds down: `Rate::choose`,
`crates/wz-spi-scb/src/lib.rs`), and SCLK on the instrument measures M Hz, which
agrees with N to the instrument's accuracy (decision 6). N is the firmware's own
account from the clock it claimed, and M is the only reading of it that does not
come from the firmware. On that image the chip identity (HW.9) holds, and the
traffic of HW.15 to HW.20 is run again and holds. Image 1's clock line is read for
its own N too and is recorded; it asked 1000000, the same rate as the earlier lab
session's probe, which read the identity registers at it.

HW.23. Over image 1, the control-lines line states what decision 3 states, and ten
consecutive resets of the board (by the debugger, as for HW.0; this is not a
removal of power) each reach the chip-and-PLCA line, with none of them printing
`wz: t1s: the bus failed during the bring-up` or `wz: FAIL - the LAN865x did not
signal the end of its reset on IRQ_N`. Ten is this procedure's choice and not a
figure of the chip: the open relies on a timing the data sheet gives no value for
(the module comment in `rust/src/mac_lan865x.rs` states the assumption), so one boot
proves little. With the reset line wired, the node holds RESET_N low and then waits
for IRQ_N to assert, so ten boots that get past the wait say that IRQ_N is
active-low as the code reads it (`boards/kit_t2g_b_h_lite/mikrobus_t1s_lines.c`), and
that the level first read after the release was not a stale assertion (that would end
the wait at once, start the open early, and fail on the bus with the line above). With
the reset line not wired the chip is reset only by its soft reset, and the record
says so.

HW.24. Needs the interrupt line wired and the instrument (decisions 3 and 6); a lab
whose line is not wired prints `HW.24 interrupt line not wired, nothing read - OK`
and names the line under what the run did not settle. With RESET_N and IRQ_N on the
instrument at a boot of image 1:

- IRQ_N is high at the instant RESET_N rises (the MCU's pull-up has had the time the
  firmware gave it; without a wired reset line there is no such instant, and this is
  not read), and low T microseconds after, T below `CONFIG_WZ_T1S_RESET_WAIT_MS`
  (10 ms by default). T is recorded: the data sheet gives no such time.
- IRQ_N idles high while the node runs.
- On a segment with nothing sent in a window of W seconds (W at least 10, and both
  captures show no frame in it), the chip-select of SCB3 is asserted at most
  2 * (W / I + 1) times, I being `CONFIG_WZ_T1S_SERVICE_MS` in seconds: with the
  line wired and the chip quiet a receive costs no exchange
  (`crates/wz-oa-tc6/src/lib.rs`, `Tc6::set_interrupt_probe`), and the housekeeping
  is one footer exchange and one register read per interval
  (`crates/wz-eth-lan865x/src/lib.rs`, `Lan865xMac::service`). C, the number
  counted, is recorded. A window with a frame in either capture is not a window of
  silence and is repeated.

HW.25. On image 3, the chip-and-PLCA line ends `PLCA off`; no housekeeping line has a
`phy status` other than 0x0000 (with PLCA off the register is not read:
`ServiceReport::phy_status`); and the identity and the T1S traffic steps (HW.9, HW.15
to HW.20) are run again and hold, against a peer that is also on plain CSMA/CD.

### What the ledger entry holds for these steps

Everything the entry holds for HW.0 to HW.7, and in addition:

- the role of each node, as roles and not names: the board's node (its PLCA id and
  count or off, its T1S address and netmask, its gateways, whether its stations were
  given or drawn, which control lines are wired), the peer (what it is, its address
  on the segment, its PLCA role and id, what it reported of its PLCA state), and the
  machine that ran the routers;
- the sha256 of EVERY image the board ran, as flashed: the CM0+ launcher, image 1, and
  image 2 and image 3 when they were built, each with the overlay files it was built
  with by name and the command that built it with its flags (never with
  `t2g_t1s_build_values.conf`);
- a sentence for every step HW.0 to HW.25, each ending ` - OK`, naming the image it was
  printed on where it was run on more than one (outside the sentence, so that the
  sentence stays as the grammar has it);
- the console lines the sentences quote, verbatim: the two station-address lines, the
  control-lines line, the SPI-clock lines of image 1 and 2, the chip-and-PLCA line of
  image 1 and 3, the ready line, and every housekeeping line of the pull and the
  return;
- the instrument readings of HW.22 and HW.24 with the instrument and its accuracy, and
  the peer's reading of its own PLCA state if it has one;
- what the run did not settle, which names at least: a control line that is not wired,
  the number of nodes the segment had against the number PLCA was told (a two-node
  segment says nothing about eight), the throughput (the steps check that frames
  cross, not how many), a start after the board's power was removed, and a peer that
  reported nothing of its PLCA state.

The table row for the T1S link carries the hash of image 1, with the date and who as
keys of its `witness`, as any HARDWARE row does; the other images' hashes appear in
the entry's text.

## The transmit pool image: steps HW.26 to HW.30

The onboard RMII image built with `overlays/t2g_tx_pool.conf`
(`CONFIG_WZ_CYT4BF_TX_POOL`, ARCHITECTURE section 9.1). The session encodes each
outbound datagram into a slot of a transmit pool in Zephyr's non-cacheable section,
lwIP writes the headers in front of it in the same slot, and the MAC's transmit
descriptor is written with the slot's address. What these steps have to show is that
a frame left the board from a pool slot read by the controller, and not from a copy
in the MAC's ring, and that its bytes were right. Nothing here has run on a board when
this is written: every line quoted was read out of the firmware source.

The row for this image names HW.26 to HW.30 in its `verdict_steps`. HW.26 stands for
the onboard verdict on THIS image, which is another image than the onboard row's, and
it does not name those steps, so that the row's steps are one range.

### Console lines these steps read

Printed by `deploy/zephyr-admin-node/rust/src/mac_cyt4bf.rs`, each on its own line:

```
pool place   ^wz: eth0: transmit pool of 8 slots at (0x[0-9a-f]{8}) to (0x[0-9a-f]{8}), in the non-cacheable section (0x[0-9a-f]{8}) to (0x[0-9a-f]{8}), read in place by the MAC$
tx counts    ^wz: tx-pool: in place ([0-9]+), copied ([0-9]+), last descriptor (0x[0-9a-f]{8}|none); pool lent ([0-9]+), started ([0-9]+), completed ([0-9]+), unarmed ([0-9]+), abandoned ([0-9]+), free ([0-9]+) of 8$
```

The pool line is printed once, before the PHY is looked for. A counts line is printed
at most every 10 seconds, and only when a count moved. `in place` and `copied` are the
MAC's own count of frames it handed the controller to read where they lie and of
frames it sent from a copy in its ring; `last descriptor` is the address the first
descriptor of the last in-place frame was written with, read back from the
descriptor. The pool's counts are the generated lifecycle's edges: `lent` slots
acquired for an encode, `started` frames a MAC queued to read in place out of a slot,
`completed` of those reported done, `unarmed` frames sent from a slot that no MAC read
in place, `abandoned` slots lent and given back unsent.

### The steps

```
HW.26 the onboard verdict held on the transmit pool image: its eight onboard sentences each ended OK on this image
HW.27 the pool sits where the MAC reads it uncached: slots <start> to <end> inside the non-cacheable section <section start> to <section end>
HW.28 a frame left from a pool slot read in place: in place <I> and started <S> above zero, last descriptor <address> inside the pool
HW.29 every slot came home: on every counts line lent minus abandoned, completed and unarmed is 8 minus free, and started minus completed is at most 4
HW.30 the frames read out of slots were right on the wire: <N> of <N> datagrams from the node in the capture had valid IPv4 and UDP checksums and decoded as zenoh
```

### How each step is read

HW.26. The record holds the sentences of HW.0 to HW.7 printed on this image, each
ending ` - OK`, outside this step's sentence.

HW.27. From the pool line: the slots' end minus start is 12288 (8 times 1536), and
start and end lie inside the section's bounds. The section bounds are Zephyr's own
linker symbols (`_nocache_ram_start`, `_nocache_ram_end`), the section the MAC's
descriptor rings are in and that `CONFIG_NOCACHE_MEMORY` has the MPU mark
non-cacheable.

HW.28. After a host has held a session with the node for at least 30 seconds (HW.1 to
HW.5 leave one), the last counts line has `in place` and `started` above zero, and its
`last descriptor` lies at or after the pool's start and before its end. `copied` is
above zero too, and is not a failure: ARP and the frames lwIP sends from its own heap
are copied on purpose, because they are in cached memory this board does not clean.
A run in which `in place` stays zero has not exercised the pool, whatever else held.

HW.29. Each counts line is consistent with itself: `lent` minus `abandoned`,
`completed` and `unarmed` equals 8 minus `free` (the slots out at that moment), and
`started` minus `completed` is at most 4 (the frames the MAC's transmit ring can hold).
A line that breaks either is a slot the lifecycle lost.

HW.30. A capture on the host's adapter over the same session: every datagram from the
node's address has a valid IPv4 header checksum and a valid UDP checksum, and the
stock router decoded the session (it is established in HW.5). A frame whose bytes came
from a cache line the controller could not see would fail here and not in HW.28,
which is why both are steps.

### What the ledger entry holds for these steps

Everything the entry holds for HW.0 to HW.7, and the pool line and every counts line
of the boot, verbatim, the capture's file name and its count of datagrams, and what
the run did not settle: at least a frame that needed IP fragmentation (none does at
this batch size), the pool running dry under load (the lend then falls back to
lwIP's heap, and the counts say how often), and a start after the board's power was
removed.

## The receive pool image: steps HW.31 to HW.35

The onboard RMII image built with `overlays/t2g_rx_pool.conf`
(`CONFIG_WZ_CYT4BF_RX_POOL`, ARCHITECTURE section 9.2). The MAC's receive descriptors
are armed with slots of a receive pool in Zephyr's non-cacheable section, a received
frame is lent to lwIP in the slot the controller wrote it into, the descriptor is armed
again with another slot, and the session socket keeps a lent datagram as it arrived, so
the session loop dispatches it from the slot. What these steps have to show is that
frames arrived in pool slots, that the session read its datagrams there and not from a
copy, and that no slot was lost. Nothing here has run on a board when this is written:
every line quoted was read out of the firmware source.

The row for this image names HW.31 to HW.35 in its `verdict_steps`. HW.31 stands for
the onboard verdict on THIS image, which is another image than the onboard row's, and
it does not name those steps, so that the row's steps are one range. Its HW.7 is the
stack measurement of the session loop's in-place receive, which dispatches a datagram
from inside the socket's lend and so runs one call deeper than the copying loop.

### Console lines these steps read

Printed by `deploy/zephyr-admin-node/rust/src/mac_cyt4bf.rs`, each on its own line:

```
pool place   ^wz: eth0: receive pool of 16 slots at (0x[0-9a-f]{8}) to (0x[0-9a-f]{8}), in the non-cacheable section (0x[0-9a-f]{8}) to (0x[0-9a-f]{8}), written in place by the MAC$
rx counts    ^wz: rx-pool: lent ([0-9]+), returned ([0-9]+), refused ([0-9]+), dropped ([0-9]+), copied ([0-9]+); pool free ([0-9]+), in the ring ([0-9]+), of 16; lwIP took ([0-9]+) lent, ([0-9]+) copied; the session read ([0-9]+) in place, ([0-9]+) copied$
```

The pool line is printed once, before the PHY is looked for. A counts line is printed
at most every 10 seconds, and only when a count moved. The first five counts are the
MAC's: frames it lent from a slot, lent frames given back, descriptors it took a frame
out of and could not arm again because every slot was out, frames it dropped whole (not
one buffer long), frames it copied out (none on this image, whose lwIP takes every frame
lent). `pool free` is the generated pool's own count of free slots and `in the ring` the
slots the receive descriptors hold. `lwIP took` is the shim's count of frames it wrapped
in place and of frames it copied into a pbuf of its own (a frame past the eight it holds
lent at once). `the session read` is the session socket's count of datagrams the session
loop read in their slot and of datagrams it copied (a datagram reassembled from
fragments, or one that did not arrive lent).

### The steps

```
HW.31 the onboard verdict held on the receive pool image: its eight onboard sentences each ended OK on this image
HW.32 the pool sits where the MAC writes it uncached: slots <start> to <end> inside the non-cacheable section <section start> to <section end>
HW.33 frames arrived in pool slots and the session read them there: lent <L>, lwIP took <T> lent and the session read <I> in place, each above zero
HW.34 every slot came home: on every counts line free, in the ring and lent minus returned add up to 16, and in the ring is at most 8
HW.35 nothing on the session's path was copied: on the last counts line refused, lwIP took copied and the session read copied are each 0
```

### How each step is read

HW.31. The record holds the sentences of HW.0 to HW.7 printed on this image, each
ending ` - OK`, outside this step's sentence.

HW.32. From the pool line: the slots' end minus start is 24576 (16 times 1536), start
is a multiple of 32, and start and end lie inside the section's bounds. The section
bounds are Zephyr's own linker symbols (`_nocache_ram_start`, `_nocache_ram_end`), the
section the MAC's descriptor rings are in and that `CONFIG_NOCACHE_MEMORY` has the MPU
mark non-cacheable.

HW.33. After a host has held a session with the node for at least 30 seconds (HW.1 to
HW.5 leave one), the last counts line has `lent`, `lwIP took ... lent` and `the session
read ... in place` above zero. The sessions of HW.1 to HW.5 are held with the datagrams
the session read in place, so a frame read from a stale cache line would have failed
those steps; this step says the datagrams were read there at all.

HW.34. Each counts line is consistent with itself: `pool free` plus `in the ring` plus
`lent` minus `returned` equals 16 (every slot is free, held by a descriptor, or lent to
lwIP at that moment), and `in the ring` is at most 8 (the descriptors). A line that
breaks either is a slot the lifecycle lost.

HW.35. On the last counts line `refused` is 0 (the ring was never left without a slot),
`lwIP took ... copied` is 0 (every frame was taken in place) and `the session read ...
copied` is 0 (every datagram the session read, it read in its slot). At the bench's
batch size no datagram needs IP fragmentation; a run that drove one would see it here,
counted, and that is the documented copy and not a failure of the slot path, so a record
that drove fragments states it and quotes the counts.

### What the ledger entry holds for these steps

Everything the entry holds for HW.0 to HW.7 (with the stack line of HW.7 quoted), and the
pool line and every counts line of the boot, verbatim, and what the run did not settle:
at least the pool running dry under load (the descriptor is then left unarmed and the
controller drops the frame, and `refused` says how often), a datagram reassembled from
fragments, the 10BASE-T1S interface beside it (whose MAC does not lend, so its frames are
copied in and counted), and a start after the board's power was removed.
