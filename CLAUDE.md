# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`README.md` covers the same ground for a human arriving at the repository, and states the
counts with the date they were measured. Where the two disagree, re-derive from the tree —
this file carried a 119-case count and an 11-entry port table for weeks after both were wrong.

## What this repository is

`MscsUnitTests` is the **test suite** for the Msgcore and TargetCore libraries of the MSCS
solution. It contains no library code — every `.cpp` here is either a suite compiled into the
`unit_suite` runner or a standalone harness registered with CTest.

**It cannot be built on its own.** It is a CMake *subdirectory script*, pulled in by
`../CMakeLists.txt` (the MSCS solution root), and it expects the targets `msgcore`,
`targetcore` and `p2pplatform` to already exist. Build and test from the solution root
(the directory that contains this one), never from here.

Scope was narrowed on 2026-08-14: the TreeFS / replication / blob / P2PeerUtilityHubs / DSP
suites moved to the sibling `MscsUnitTestsExternal`, so this directory links `msgcore +
targetcore + p2pplatform` and nothing else. Do not add a test here that needs `treefs`,
`p2putilhubs` or `dspchain` — that is what the split was for.

## Build & test

Configure/build/test are driven by the solution-root `CMakePresets.json`:

```powershell
# from the MSCS solution root
cmake --preset windows-msvc              # requires MSCS_BUILD_LIBS=ON (preset sets it)
cmake --build --preset windows-msvc-debug
ctest --preset windows-msvc-debug        # the preset supplies the DLL PATH
```

Linux presets: `linux-gcc-debug`, `linux-clang-debug`, `linux-gcc-asan`, `linux-gcc-tsan`
(plus matching build/test presets).

Running a single test, or a subset:

```powershell
ctest --preset windows-msvc-debug -R p2p_authspoof --output-on-failure
ctest --preset windows-msvc-debug -N            # list registered tests, run nothing
ctest --preset windows-msvc-debug -LE security  # everything except the gate tests
ctest --preset windows-msvc-debug -L  security  # only the gate tests
```

A single unit case cannot be selected — `unit_suite` is one exe that runs all three suites.
Run the exe directly (`build/windows-msvc/MscsUnitTests/Debug/unit_suite.exe`) and read the
per-case lines.

Reproducing a fuzz finding: `p2p_fuzzframe 0x5EEDF00D --replay <case> <iter>`. The seed in
`CMakeLists.txt` is fixed on purpose so a red CI line replays exactly.

Sanitizer runs (Linux only, not gated by ctest): `./run_sanitizers.sh [address|thread]`,
which builds `teardown_stress` with the sanitizer applied globally and runs it.

### The Windows MSBuild path

`MscsUnitTests(2026).vcxproj` / `.sln` build the same three suites into a `MscsUnitTests.exe`
via MSBuild, as an alternative to CMake. It is Debug|x64 only, uses a PCH (`stdafx.cpp`
creates it — CMake builds without one), and its PreBuildEvent runs `CheckSuiteWiring.ps1`.
**Any suite added to `TestMain.cpp` must be added to BOTH `CMakeLists.txt` and this
.vcxproj**; commit a5e9195 added a suite to only one and all 193 cases were dark on Windows
for 14 days.

### Repo self-checks (what CI actually runs)

`.github/workflows/repo-invariants.yml` **compiles nothing and runs no test** — the sibling
dependencies are not reachable from a runner. It checks wiring only:

```powershell
python .github/ci/check_repo_invariants.py                 # sources wired, no POST_BUILD, .gitattributes, hook, STATUS declared
./CheckSuiteWiring.ps1 -ProjectDir . -ProjectFile 'MscsUnitTests(2026).vcxproj' -VerboseReport
cmake -S .github/ci/parse-check -B <tmp>                   # generate against stub siblings
```

Run `check_repo_invariants.py` after adding or removing any `.cpp` here. Read a green CI tick
as "the wiring is intact", never as "the tests pass" — every quoted ctest figure comes from a
developer running it by hand.

There is a fourth check CI **cannot** run, because it needs a real test run. Do this after any
ctest run whose result you intend to quote — it compares each `security` test's declared
`STATUS` against what actually happened, and is the only thing that catches a banner claiming
a finding is open weeks after it was fixed:

```powershell
ctest --test-dir <build>\MscsUnitTests -C Debug --output-junit results.xml
python .github/ci/check_repo_invariants.py --ctest-junit results.xml
```

Install the pre-push hook per clone: `git config core.hooksPath tools/hooks`. It keeps master
fast-forward-only and refuses any SHA that has not gone green in the workflow.

## Architecture

### The runner (`unit_suite`)

- `TestMain.cpp` — entry point; calls `RunMsgcoreSuite()`, `RunMsgcoreCApiSuite()`,
  `RunTargetCoreSuite()`. **125 cases** (70 Msgcore, 19 Msgcore C-API, 36 TargetCore),
  counted 2026-09-08. It was 119 until then; recount rather than trust this line.
- `TestFramework.cpp/.h` — `TF_CASE` / `TF_CHECK` / `TF_CHECK_EQ`, plus the process-wide
  lifecycle: one `CWinApp` (MFC allows exactly one per exe), `StartupP2Pmsg`/`CleanupP2Pmsg`,
  Winsock, and an assert hook that folds a CRT/MFC ASSERT into a recorded failure instead of a
  modal dialog that would hang a headless run.
- `TestFramework.cpp` is compiled **by path** into `MscsUnitTestsExternal`'s runner too. There
  is one copy on purpose; this tree has repeatedly been bitten by duplicated build/config code
  drifting apart. Same for `MscsTestCommon.cmake` and `CheckSuiteWiring.ps1` (parameterised by
  `-TestMainFile` rather than copied).

### Standalone harnesses

Everything else is one translation unit, one executable, **verdict = process exit code**.
Conventions across them:

- `0` pass, `1` fail, `2` incomplete (suites compiled out — a reduced run is never green),
  `3` inconclusive (a positive control failed, or a timeout that must not read as a pass).
- Each security/gate harness opens with an **inline positive control**, because a refused
  message and a dead transport are both just silence.
- A gate test encodes the **requirement**, not the current behaviour, so it is written to be
  red until the fix lands. **Never add `WILL_FAIL`** — that makes CI green on an open hole and
  red the day somebody fixes it. They carry `LABELS security` so a known-state run can exclude
  them with `-LE security`.
- Every `security` test declares its expected verdict in its `CMakeLists.txt` banner:
  `#   STATUS: PASSES` or `#   STATUS: EXPECTED-FAIL`. This is enforced — see
  "Repo self-checks" above. **As of 2026-09-08 there are 37 `security` tests and all 37
  declare `STATUS: PASSES` — 0 `EXPECTED-FAIL`.** `p2p_fuzzframe` was the standing exception
  and no longer is: its banner reads `PASSES CLEAN`, measured 2026-08-21 on Windows Debug +
  Release, having been `PASSES-WITHIN-BUDGET` and `EXPECTED-FAIL` before that. Those are
  *declarations*, not a run — `check_repo_invariants.py --ctest-junit` is what compares them
  against one. When you change a test's verdict, change its `STATUS` in the same commit and
  say what closed it.
- `p2p_fuzzframe` is registered **with `--strict-assert`**, which promotes a tripped ASSERT
  from a printed diagnostic to a verdict. Without it the harness exits 0 having tripped ~7,900
  asserts — each one wire data violating an invariant the code believes, reached pre-auth —
  and that is how it read green for as long as it did. Do not drop the flag to get a green
  board.
- `p2p_authancestor` asserted a documented **gap**, not a protection, until 2026-08-14. It now
  asserts the protection that closes it (`RequireRelayAuth(true)` — the source bound to the
  ORIGIN's signature instead of to the peer that delivered) AND, in one phase, the old
  behaviour that a tree which has not opted in still gets. Four hubs, because a message can
  only arrive from outside its parent's subtree honestly if the parent got it from ITS parent.
- Each socket harness takes its port as argv[1] and holds a `RESOURCE_LOCK loopback_<port>`
  so ctest never runs two on the same port. **Allocated, re-derived from `CMakeLists.txt`
  2026-09-08 — 37 locks, not the 11 this list carried until then:**

  | port | harness | | port | harness |
  |---|---|---|---|---|
  | 7811 | `alex_test`      | | 7838 | `p2p_authposture` |
  | 7813 | `p2p_authgate`   | | 7840 | `p2p_confchannel` |
  | 7814 | `p2p_authspoof`  | | 7842 | `p2p_conreap` |
  | 7815 | `p2p_authpsk`    | | 7844 | `p2p_reportsign` |
  | 7816 | `p2p_authrelay`  | | 7845 | `p2p_reportsign` |
  | 7818 | `p2p_sealhop`    | | 7846 | `p2p_sealbcast` |
  | 7819 | `p2p_expreg`     | | 7847 | `p2p_listenscope` |
  | 7820 | `p2p_authancestor` | | 7848 | `p2p_acceptfilter` |
  | 7821 | `p2p_authancestor` | | 7849 | `p2p_resolve` |
  | 7823 | `p2p_bigreport`  | | 7850 | `p2p_ipv6` |
  | 7824 | `p2p_keyrotate`  | | 7851 | `p2p_ipv6dual` |
  | 7826 | `p2p_acceptcap`  | | 7852 | `p2p_ipv6filter` |
  | 7827 | `p2p_logindeadline` | | 7853 | `p2p_linktrust` |
  | 7828 | `p2p_srcbound`   | | 7854 | `p2p_linktrust` |
  | 7830 | `p2p_revokedist` | | 7855 | `p2p_linktrust` |
  | 7833 | `p2p_hubwake`    | | 7856 | `p2p_linktrust` |
  | 7834 | `p2p_hubsnap`    | | 7857 | `p2p_linktrust` |
  | 7835 | `p2p_backpressure` | | 7858 | `p2p_linktrust` |
  | 7836 | `p2p_authchannel`  | | | |

  **Free in range: 7812, 7817, 7822, 7825, 7829, 7831, 7832, 7837, 7839, 7841, 7843**, then
  7859 up. Take one of those for anything new. Do **not** infer a free port from the end of
  this table — that is precisely how the old list misled, since it stopped at 7824 while
  7826–7858 were already taken. Re-derive with
  `grep -oE "loopback_[0-9]+" CMakeLists.txt | sort -u` rather than trusting the table.

### Cross-platform shape

The suites and most harnesses are portable and gate on both toolchains. Platform-specific
pieces: `linux-shim/COleTime_Ext.h` stands in for MsgcoreMFC's real header on Linux (on
Windows `MsgcoreMFC/COleTime_Ext.cpp` + `CTime_Ext.cpp` are compiled *into* `unit_suite` with
`MsgcoreMFC_EXPORTS`); `com232_mesh`, `teardown_stress` and `perf_ab` are Linux-only;
`seal_interop` is registered on Windows only and verifies the checked-in `vectors/*.vec`
sealed by the *other* backend. `golden_ref.p2p` is a binary serialized heap image compared
byte-for-byte across OSes — `.gitattributes` marks it `binary` and the invariants script
enforces that line's presence.

## Rules that are easy to break

- **Never add a `POST_BUILD` copy of `msgcore.dll` / `targetcore.dll` next to the test exes.**
  Windows searches the application directory before PATH, so such a copy silently shadows the
  library ctest just built and a fix can be "verified" green without ever being loaded. The
  loader path is set by `_mscs_apply_loader_path()` in `MscsTestCommon.cmake`; the invariants
  script fails the build if a `POST_BUILD` step appears in `CMakeLists.txt`.
  (The legacy `.vcxproj` does copy DLLs into its own `x64\Debug\` — that is the MSBuild path's
  own output dir, separate from the CMake build tree.)
- `_mscs_apply_loader_path()` must stay the **last** line of `CMakeLists.txt`: it reads the
  directory's accumulated `TESTS` property, so anything registered after it is uncovered.
- Every `.cpp` in this directory must be referenced by `CMakeLists.txt` or listed in
  `KNOWN_UNWIRED` in `check_repo_invariants.py` **with a reason** — and the allowlist is
  checked in both directions, so a stale entry fails too.
- Test comments here carry the *evidence* for why a test exists (the finding, the commit, the
  measured failure). Preserve that when editing; the file header is often the only record.

## License

Copyright 2026 Khrustal & Mann, MELBOURNE, VICTORIA, AUSTRALIA, 3000.

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the
full text.
