# Making and checking a release

A release of watching-zenoh is a `v*` tag. `.github/workflows/release.yml` runs on the push of
the tag (or on a manual dispatch naming an existing tag) and does three things:

| Job | What it does |
|---|---|
| `release` | the CI mirror (`scripts/run-ci.sh` layers), the `cargo publish --dry-run` of each publishable crate, then a **draft** GitHub release of the tag with generated notes |
| `windows-packages` | the Windows packages of the pico C ABI library, one row per width (`x64`, `x86`), each the one library built without Rust's standard library (`nostd`): each built and then tested from its own zip, with the composite action `.github/actions/pico-windows-package` |
| `windows-packages-attach` | after both: holds the two packages to the tag and its commit, writes `SHA256SUMS`, and attaches the zips, their `.zip.sha256` files and `SHA256SUMS` to the draft release |

The Platform workflow's `package-windows` job runs the same composite action on every push that
touches what the package is made from, so the steps a release builds a package with are the steps
that job reads every push; they are written once.

**The form a release carries.** The library without `std` (`os-windows`, the `capi-nostd` profile),
as one DLL, is the only form a release carries (owner, 2026-11-23:
`docs/c-abi-engine-and-memory.md`, E7). `package-windows` also builds the library with `std`, in
the one-library and the split form, to compare and measure against; no release carries those, and
the attach job refuses a set that holds one. The split form is not released because its additional
library (`wz-capi-pico-ext`) has no form without `std`.

A package that fails its build or its test fails the release run and nothing is attached: no step of
the package jobs is soft, and the attach job needs every row.

## The tag

`v<version>` or `v<version>-<suffix>`, where `<version>` is `version` under
`[workspace.package]` in `crates/Cargo.toml` (the version every package's name and manifest carry).
For version 0.1.0: `v0.1.0`, or `v0.1.0-rc1` for a candidate. A tag that names another version is
refused by the attach job (`pico_windows_package.py --release`), after the packages are built; read
the version before tagging. A suffix containing `-rc`, `-beta`, `-alpha` or `-mvp` marks the
release a prerelease.

The workflow, the composite action and the packager are read from the TAGGED tree, so the tag must be
on a commit that already has the `windows-packages` jobs; a tag on an older commit gets the release
of that commit's `release.yml`.

## Cutting a release

Only the maintainer pushes a tag.

1. Pick a commit on `main`. Its Platform run's `package-windows` rows `nostd` show whether the
   packages build and pass their test there; a red row there will be a red release.
2. Tag it and push the tag:

   ```
   git tag -a v0.1.0 -m "v0.1.0" <commit>
   git push origin v0.1.0
   ```

   Or, for a tag already pushed, dispatch the Release workflow with `tag` set to it
   (`gh workflow run release.yml -f tag=v0.1.0`).
3. Wait for the run. When it is green, the draft release of the tag carries, for each of the two
   packages, `wz-capi-pico-<version>-host-peer-ext-windows-<arch>-nostd-<commit>.zip` and its
   `.zip.sha256`, and one `SHA256SUMS` naming the two. `<commit>` is the first ten digits of the
   tagged commit.
4. Read the draft and publish it. The release job makes a draft on purpose: publishing is the
   maintainer's decision.

If a row fails, the draft exists with no packages. Re-running the failed jobs rebuilds from the same
commit; a fix that needs a new commit needs a new tag.

The run's artifacts expire after seven days; the assets of the release stay until the release is
deleted.

## Checking a release's packages

Anyone with the release's files can check them:

1. That each zip is the one the workflow attached: in the download directory,
   `sha256sum -c SHA256SUMS` (`shasum -a 256 -c SHA256SUMS` on macOS; in PowerShell,
   `Get-FileHash -Algorithm SHA256 <zip>` and compare with its line).
2. That a package holds what its manifest says: from a checkout of the tag,
   `python3 scripts/lib/pico_windows_package.py --verify <zip>` re-hashes every file of the package
   against its `manifest.json` and names a file that differs, is missing or is not listed. It runs on
   any host.
3. That the set is the release: from a checkout of the tag, with the two zips and their
   `.zip.sha256` files in one directory,
   `python3 scripts/lib/pico_windows_package.py --release <dir> <tag>` repeats the attach job's check
   (one package of every width in the form a release carries and none of another, each matching its
   `.zip.sha256` and its manifest, built from the tagged commit with no uncommitted change, of the
   version the tag names) and writes `<dir>/SHA256SUMS`, which then equals the attached one.

What this does not prove: the digests are attached by the same workflow that built the packages, so
they show a download is intact, not who made it. The packages are not signed (`RELEASE-NOTES.md` in
each package says so).
