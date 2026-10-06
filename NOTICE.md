# NOTICE — teams-core provenance

This repository is `ost` — the Open Source Teams protocol library in Rust —
extracted from the vendored copy inside [better-teams]
(https://github.com/mrowlinson/better-teams) (`rust/ost/`, as of
commit `ce451cc`, 2026-09-30, subtree-split with `git-filter-repo
--subdirectory-filter`).

## Chain of custody

1. **eisbaw/ost** — original "OST client" (Open Source Teams), MIT License,
   by Mark Ruvald Pedersen. Last upstream commit 2026-02-06. Upstream is
   inactive; its `rust/ost/LICENSE` (MIT) is preserved at `./LICENSE`.
2. **mrowlinson/better-teams** — vendored `rust/ost/` + **92 patches**
   documented in `./OSTMAC-PATCHES.md` (35 `[major]`, 56 `[minor]`): library
   surface (`src/lib.rs`), Trouter event hub (`src/event_hub.rs`), 16 new API
   modules (calendar, files, recordings, transcripts, planner, tags, …),
   macOS A/V bridge (`src/calling/macav.rs`, pure Rust), test fakes.
   Per better-teams' NOTICE, the vendored `rust/ost/` tree remains under its
   own MIT License; better-teams' "MIT with Microsoft exclusion" license
   covers only their original code (`swift/`, `rust/ostmac-core/`), **none of
   which is included here**.
3. **teamsfast/teams-core** (this repo) — Linux enablement and ongoing
   maintenance. Our own changes are MIT, same as the tree we build on.

## Status of files

- Every file in this tree is MIT-licensed (no per-file headers; they inherit
  `./LICENSE`, the original eisbaw/ost MIT text, kept verbatim).
- `OSTMAC-PATCHES.md` is kept as the authoritative history of the 92 patches
  this tree carries relative to eisbaw/ost.
- Not affiliated with Microsoft. Unofficial client; use at your own risk.

## Upstream sync

Base point tag: `sync/better-teams-2026-09-30`. Future syncs re-run the
subtree split of `better-teams:rust/ost` and `git merge` — the filter is
deterministic, so rewritten history merges with a common ancestor.
