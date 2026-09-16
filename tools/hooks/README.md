# tools/hooks

Git hooks for this repository, tracked so they can be reviewed and so a fresh clone can
install them. Git does not run anything from here until you point it at this directory —
`.git/hooks/` is what Git executes, and it is not version-controlled.

## Install

```sh
git config core.hooksPath tools/hooks
```

Per clone, and per developer. There is no way to make a hook install itself; a repository
that could run code on clone would be a supply-chain hole, not a feature.

To uninstall: `git config --unset core.hooksPath`.

## `pre-push`

Keeps three things off `master`: deletion, non-fast-forward pushes, and any commit whose
exact SHA has not already gone green in the [`repo-invariants.yml`](../../.github/workflows/repo-invariants.yml)
workflow. Other branches push freely, which is deliberate — pushing a branch is how CI gets
to run at all.

The third rule implies the workflow a server-side required-status-check would have forced:

```sh
git switch -c fix-something
git push -u origin fix-something      # CI runs on this SHA
# ... wait for green ...
git switch master
git merge --ff-only fix-something     # SHA preserved, so it stays green
git push
```

`--ff-only` is load-bearing. A merge commit is a new SHA that CI has never seen, and the
hook refuses it exactly as it refuses any other unverified commit.

It is a hook on one machine, not branch protection: `--no-verify` skips it by design, and
anyone who can push can delete it. It stops the accident, not the intent. Server-side rules
are unavailable because GitHub Free does not offer them on private repositories.

## What green actually means here

Read this before treating a passed hook as "master is good". It does not mean that, and the
gap is wider in this repository than in either sibling.

**This repository is the MSCS test suite, and CI cannot build it.** A build needs `Msgcore`,
`Targetcore`, `Platform`, `TreeFs`, `P2PeerUtilityHubs`, `DspChain` and the solution-root
`CMakeLists.txt`. Only the first two are on GitHub. `Platform`, `P2PeerUtilityHubs` and
`DspChain` have **no git remote at all**, and `TreeFs` lives on a private non-GitHub host. The
closure simply does not exist anywhere a runner can reach it.

So `repo-invariants.yml` **never compiles a translation unit and never runs a test**. What it
does check is real, and each check exists because the matching defect has already shipped here:

| Job | What it would have caught |
|---|---|
| `invariants` | `p2p_u8_smoke.cpp` back in the tree with no `add_test` entry; a `POST_BUILD` copy recreating the stale-DLL hazard; `golden_ref.p2p` losing its `binary` attribute |
| `suite-wiring` | `a5e9195` — `UtilHubsSuite.cpp` added to `TestMain.cpp` and not to the `.vcxproj`, so all 193 cases were dark on Windows for 14 days while CMake stayed green |
| `cmake-parse` | a test registered against a source file nobody added; a duplicate `add_test` name |

Every ctest figure this project quotes — Windows 41/41, Linux 44/44 — comes from a developer
running `ctest` by hand on their own machine, and from nothing else.

**Read the tick as "the wiring is intact", never as "the tests pass".** Closing that gap needs
remotes for the three unpublished dependencies; until then, no honest workflow here can do
better, and one that appeared to would be worse than none.

## License

Copyright 2026 Khrustal & Mann, MELBOURNE, VICTORIA, AUSTRALIA, 3000.

Licensed under the Apache License, Version 2.0. See [`LICENSE`](../../LICENSE) for the
full text.
