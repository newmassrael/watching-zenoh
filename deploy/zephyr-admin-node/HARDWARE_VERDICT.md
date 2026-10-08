# Hardware verdict for the Zephyr admin node

This is the grammar a lab uses to say that the admin node runs on a board. A row
of `deploy/zephyr-boards.json` for this app is HARDWARE only when a ledger entry
holds a run that printed every step below, and `scripts/lib/zephyr_board_table_gate.py`
reads the entry for exactly these step names.

The steps are the ones Layer Qza puts to the emulated node: its body is
`_qa_scenario` in `scripts/run-ci.sh`, labelled `Qza`. A lab runs the same
checks against the board with the label `HW`. Two sentences carry an address of
the lab's network where the emulator lane carries its own (HW.4 and HW.5);
nothing else differs.

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
sentences compare them.

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
- the eight sentences above, each ending ` - OK`;
- what the run did not settle.

The table row carries the same hash, date and who as keys of its `witness`, and
the gate refuses a hash that does not appear in the entry. A row that requires
companions is HARDWARE only together with them, and they cite the same entry:
what ran was the images together, and one image's record says nothing about the
pair.
