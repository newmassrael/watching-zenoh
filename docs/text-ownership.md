# The text of an image, by owner

`deploy/text_budget.json` holds, for each gated MCU image, its text and the bytes of every owner of
its symbol table; `scripts/lib/text_owner_gate.py` reads them out of the linked ELF in the kit lane's
build step and refuses an image that moved by more than a tolerance. This is the text twin of the
resource budget (`deploy/resource_budget.json`): a change that moves a row moves it in the same
commit, with the reason.

## Why it exists

The parity matrix says the fixed client's text is 1.20 of single-threaded zenoh-pico's. That is a
total. Which of the 31 KB of difference is whose was not written anywhere, so a lever on size was
chosen by a guess about where the bytes were, and its worth could be read only as a change of the
total. Measured: the machine outliner saves 2.2 KB and costs 5.1 us in the answer to a query
(`recvfrom` to `sendto` 41.7 to 46.8 us); the Declare dispatch merge saved 2.2 KB and cost 24 B of
stack. Neither could be weighed against the other without knowing what the rest of the 31 KB is.

## How an owner is read

`nm -S -C` of the ELF; every symbol of code or read-only data is given to an owner. A Rust symbol
belongs to the first crate its demangled path names; a C symbol to its prefix, written as the
prefix (`c:_z_`), because a prefix is a fact about a name and not a claim about a library (`z_` is
Zephyr's internals and zenoh-pico's API alike).

What this is not: provenance. With link-time inlining the symbol that carries a function's code is
its caller's, so what `wz_app_main` inlines is counted under `c:wz_` (10.5 KB in the fixed image,
the largest unnamed part of the wz code). The rows fence the total and show where a change landed.
Finding whose source a byte came from takes a build without LTO, which has other sizes.

## The first reading (run 20261028T005644's compare builds)

The platform (the Zephyr network stack, the board's drivers, the toolchain) is the same size in the
fixed image and in the single-threaded pico image: the 31 KB is not there. What is left is the two
libraries' own code.

| | own code |
|---|---|
| zenoh-pico (`c:_z_` and the wz harness it is linked with) | about 55 KB |
| wz fixed client | about 92 KB |

wz's 92 KB is `wz_session_core` 41.6 KB, the inlined `wz_app_main` 10.5 KB, `wz_session_mcu` 9.4 KB,
`wz_codecs` 8.5 KB, `sce_rust_runtime` 7.9 KB, `wz_runtime_coop` 6.1 KB, `keccak` 2.2 KB, `core`
1.8 KB, `compiler_builtins` 1.6 KB (0.9 KB in the pico image) and `wz_runtime_zephyr` 0.7 KB. Zenoh-pico
carries about 6 KB of C library code wz does not, which is why the difference is 31 and not 37 KB.

## Levers this ranks (none taken here)

- `keccak` (2.2 KB, one symbol) is the SHAKE128 permutation of the initial sequence number
  (`src/initial_sn.rs`): zenoh derives it from the two zids so that a re-attempt of a multilink
  session lands on the same origin, and zenoh-pico draws it from entropy. A single-link MCU client
  does not need the derivation; a build switch between the zenoh derivation and a compact pure
  function of the two zids keeps the idempotence and drops the permutation.
- `wz_session_core` is the owner to split further, by function, before any flag is tried on it.
- The machine outliner and `opt-level=z` are weighed per tier (the answer path against the connect
  and declare paths), not on the whole image.

## Updating a row

Build the image (`bash scripts/kit-lane.sh build KEY`), print its row with
`python3 scripts/lib/text_owner_gate.py --emit KEY --elf ELF`, put it in `deploy/text_budget.json`
and say in `measured` what moved the text.
