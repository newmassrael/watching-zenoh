# Fuzz reproducers

One directory per target (`pcap/`, `live/`, `transport/`, `text/`, `proto/`,
`e2e/`, `replay/`). A file here is an input that once made its target fail;
`scripts/fuzz.sh regress` (Layer Fz of `scripts/run-ci.sh`) runs every one of
them through its target on every run, beside the seeds.

A crash found by `scripts/fuzz.sh run` is written to
`crates/target/fuzz/artifacts/<target>/`. The commit that fixes it copies that
file here, named for what it exercises, so the defect cannot come back
unseen. An input made of a tracked capture and a few bytes of arguments is not
copied: it is a line of `PINNED` in `scripts/lib/fuzz_seeds.py`, which makes it
a seed of every replay without a second copy of the capture.
