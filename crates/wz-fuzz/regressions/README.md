# Fuzz reproducers

One directory per target (`pcap/`, `live/`, `transport/`, `text/`, `proto/`,
`e2e/`, `replay/`). A file here is an input that once made its target fail;
`scripts/fuzz.sh regress` (Layer Fz of `scripts/run-ci.sh`) runs every one of
them through its target on every run, beside the seeds.

A crash found by `scripts/fuzz.sh run` is written to
`crates/target/fuzz/artifacts/<target>/`. The commit that fixes it copies that
file here, named for what it exercises, so the defect cannot come back
unseen. Two kinds are not copied here but written in
`scripts/lib/fuzz_seeds.py`, where every replay reads them as seeds: an input
made of a tracked capture and a few bytes of arguments is a line of `PINNED`
(no second copy of the capture), and a small input is its base64 in `LITERAL`
(text the fixing commit shows).
