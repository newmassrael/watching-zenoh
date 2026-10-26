# Target manifest fixtures

The corpus a reader of `wz-target-manifest.json` is tested against, and the one this tree's own gate
(`scripts/lib/wz_package.py --verify`) is held to: two readers of one contract, judged by one set of
files (`docs/target-build-contract.md` step 7). Read `index.json` first.

## What is here

- `synthetic/<case>/`: whole packages (the manifest and the files it describes), made by the entry
  from synthetic files whose contents are known, so every defect has a file that carries exactly that
  defect. The valid cases are a host package of a library and an executable, an Android package that
  bundles the C++ runtime from its SDK, and a host package of a declared node with its declaration.
  Each invalid case is one of them with one defect.
- `measured/<platform>[-<node>].json`: manifests of real builds, recorded from a committed tree. Only
  the manifest is kept (the artifacts are megabytes and change with every commit), so they are read for
  their shape and their values, not for the files.
- `index.json`: every fixture with its origin (`measured` or `synthetic`), its platform and the
  verdict this gate gives it. An invalid case names its `level` and the words of the finding:
  - `shape`: the keys of the manifest, in order, none more;
  - `manifest`: the manifest alone, read for its own consistency (the schema number, the closure of
    `bundled`, the `inputs` an artifact was built from, the paths);
  - `files`: the files the manifest describes, measured again from their bytes.

  A reader that reads only the manifest is expected to reject the `shape` and `manifest` cases and to
  accept the `files` ones, which only a reader that measures the files can see. The finding words are
  this gate's; a reader states its own reasons.

## How it is kept current

`wz_package.py --check-fixtures` (run by the entry's selftest, which the pre-push hook runs) remakes
the synthetic corpus and requires it byte for byte, the index to describe the corpus, every case to be
judged as indexed, and every measured manifest to have this schema's shape and a committed tree. A
change of the manifest's schema or of the declaration it reads therefore shows here as a diff:
`wz_package.py --write-fixtures` writes the synthetic corpus and the index again, and
`wz_package.py --record-measured DIR` records a package the entry built and verified.
