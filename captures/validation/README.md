# Validation corpus of the zenoh verdict

Real packet captures of what the calibration corpus (`captures/corpus/`) lacks,
collected after the model of the flow zenoh test was frozen
(`docs/flow-zenoh-verdict.md` §6.12, ledger round 4158) and read against that
model once (§6.13, `crates/wz-capture/src/zenoh_validation_tests.rs`). No
weight of the model is computed from them.

## How a file got here

1. Captured by `scripts/capture-validation.sh`, which keeps the whole recipe:
   - a zenoh workload runs in one container on its loopback
     (`scripts/capture-validation/zenoh-workload.sh`), with zenohd and the
     examples of the pinned release built by
     `scripts/capture-validation/build-bins.sh`, and the zenoh-c and
     zenoh-pico examples built by `scripts/capture-validation/build-c-pico.sh`;
   - a null protocol runs as its real server and client in containers on a
     docker network of their own (`scripts/capture-validation/null-workload.sh`),
     captured in the server's network namespace with this host's own traffic
     left out.
2. Anonymised by `scripts/lib/capture_anonymise.py` with scope `own`.
3. Checked: `capture_anonymise.py --verify-corpus captures/validation` holds
   every file to being one the anonymiser would leave unchanged.

`corpus.json5` lists every file, what it is, and its group: here every file is
a group of its own (29 zenoh, 29 null).
