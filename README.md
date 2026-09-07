# MscsUnitTests

The test suite for the **Msgcore** and **TargetCore** libraries of the MSCS solution.

There is no library code here. Every `.cpp` in this directory is either a case suite
compiled into the `unit_suite` runner, or a standalone harness registered with CTest
whose verdict is its process exit code.

## This repository cannot be built on its own

It is a CMake *subdirectory script*, not a project. It has no `project()` call, and it
expects the targets `msgcore`, `targetcore` and `p2pplatform` to already exist — so
configuring this directory directly fails, and that is the intended behaviour rather
than a missing step.

Build from the solution root, which lives in its own repository
([`MscsSolution`](https://github.com/IvywareAU/MscsSolution)) and pulls each component
in as a sibling directory:

```
MSCS\                      <- clone MscsSolution here (CMakeLists.txt, CMakePresets.json)
├── Msgcore\               <- clone Msgcore
│   └── Platform\          <- p2pplatform
├── TargetCore\            <- clone TargetCore
└── MscsUnitTests\         <- this repository
```

```powershell
# from the solution root, never from here
cmake --preset windows-msvc
cmake --build --preset windows-msvc-debug
ctest --preset windows-msvc-debug        # the preset supplies the DLL path
```

Linux presets: `linux-gcc-debug`, `linux-clang-debug`, `linux-gcc-asan`, `linux-gcc-tsan`.

Selecting tests:

```powershell
ctest --preset windows-msvc-debug -N                 # list what is registered, run nothing
ctest --preset windows-msvc-debug -R p2p_authspoof --output-on-failure
ctest --preset windows-msvc-debug -L  security       # only the gate tests
ctest --preset windows-msvc-debug -LE security       # everything except them
```

A single case inside `unit_suite` cannot be selected — it is one executable that runs all
three suites. Run the exe directly and read its per-case lines.

## What is in here

Counted from `CMakeLists.txt` and the suite sources on 2026-09-08. These are **wiring
counts, not results**: nothing below is a claim that a run was green.

| | |
|---|---|
| `unit_suite` cases | **125** `TF_CASE` — 70 Msgcore, 19 Msgcore C-API, 36 TargetCore |
| Registered CTest entries | **54**, across both platforms; a given run registers the subset its platform enables |
| Carrying `LABELS security` | **37** — every one of them declares a `STATUS`: 37 `PASSES`, 0 `EXPECTED-FAIL` |

The runner is `TestMain.cpp` over `TestFramework.cpp/.h` (`TF_CASE` / `TF_CHECK` /
`TF_CHECK_EQ`), which also owns the process-wide lifecycle: one `CWinApp`, Winsock,
`StartupP2Pmsg` / `CleanupP2Pmsg`, and an assert hook that folds a CRT/MFC `ASSERT` into
a recorded failure rather than a modal dialog that would hang a headless run.
`TestFramework.cpp` is compiled by path into the sibling `MscsUnitTestsExternal` runner
as well — one copy on purpose, because duplicated build and config code in this tree has
drifted before.

Everything else is one translation unit, one executable, verdict by exit code.

## Reading a result

**Exit codes are four-valued, and the last two exist so a non-run cannot read as a pass:**

| | |
|---|---|
| `0` | pass |
| `1` | fail |
| `2` | incomplete — suites compiled out; a reduced run is never green |
| `3` | inconclusive — a positive control failed, or a timeout that must not read as a pass |

Conventions that make those verdicts mean something:

- **Every security harness opens with an inline positive control.** A refused message and
  a dead transport are both just silence; without a control, the second looks like the
  first succeeding.
- **A gate test encodes the requirement, not the current behaviour** — so it is written to
  be red until the fix lands. **`WILL_FAIL` is never used here.** It would make CI green on
  an open hole and red on the day somebody closes it.
- **Every `security` test declares its expected verdict** in its `CMakeLists.txt` banner
  (`STATUS: PASSES` / `STATUS: EXPECTED-FAIL`), and that declaration is machine-checked
  against an actual run. It is what catches a banner still claiming a finding is open weeks
  after it was fixed.
- **`p2p_fuzzframe` is registered with `--strict-assert`**, which promotes a tripped ASSERT
  from a printed diagnostic to a verdict. Without the flag it exits 0 having tripped
  thousands of asserts — each one wire data violating an invariant the code believes,
  reached pre-auth. Do not drop it to get a green board.
- **Socket harnesses take a port as `argv[1]`** and hold a `RESOURCE_LOCK loopback_<port>`,
  so CTest never runs two on the same port.

Reproducing a fuzz finding — the seed is fixed so a red CI line replays exactly:

```
p2p_fuzzframe 0x5EEDF00D --replay <case> <iter>
```

Sanitizers (Linux, not gated by ctest): `./run_sanitizers.sh [address|thread]`.

## What CI does and does not check

`.github/workflows/repo-invariants.yml` **compiles nothing and runs no test** — the sibling
libraries are not reachable from a runner. It checks wiring only: that every source is
referenced, that no `POST_BUILD` DLL copy has appeared, that `.gitattributes` and the hook
are intact, and that each security test declares a `STATUS`.

**Read a green tick as "the wiring is intact", never as "the tests pass."** Every test
figure quoted anywhere in this repository comes from a developer running ctest by hand.

There is a fourth check CI cannot run, because it needs a real run — it compares each
declared `STATUS` against what actually happened:

```powershell
ctest --test-dir <build>\MscsUnitTests -C Debug --output-junit results.xml
python .github/ci/check_repo_invariants.py --ctest-junit results.xml
```

Install the pre-push hook once per clone: `git config core.hooksPath tools/hooks`.

## Two traps worth knowing before you edit

**Never add a `POST_BUILD` copy of `msgcore.dll` / `targetcore.dll` next to the test exes.**
Windows searches the application directory before `PATH`, so the copy silently shadows the
library CTest just built, and a fix can be "verified" green without ever having been loaded.
The loader path is set centrally instead; the invariants script fails the build if a
`POST_BUILD` step appears.

**Any suite added to `TestMain.cpp` must be added to BOTH `CMakeLists.txt` and
`MscsUnitTests(2022).vcxproj`.** The `.vcxproj` is an alternative MSBuild path building the
same suites (Debug|x64, with a PCH). A suite once went into only one of the two, and every
case in it was dark on Windows for fourteen days.

## Layout

```
MscsUnitTests\
├── TestMain.cpp  TestFramework.cpp/.h      the unit_suite runner
├── MsgcoreSuite.cpp  MsgcoreCApiSuite.cpp  TargetCoreSuite.cpp
├── p2p_*.cpp                               standalone harnesses (auth, seal, fuzz, transport)
├── *_mesh.cpp  mix_con*.cpp                per-transport mesh harnesses
├── CMakeLists.txt                          registration + the STATUS banners
├── MscsTestCommon.cmake                    compile shape, shared with MscsUnitTestsExternal
├── CheckSuiteWiring.ps1                    .vcxproj / TestMain.cpp agreement check
├── MscsUnitTests(2022).sln / .vcxproj      the MSBuild path
├── fuzz\        corpus + README            what belongs in the corpus and why
├── vectors\     *.vec                      cross-backend sealed vectors (seal_interop)
├── tools\hooks\ + README                   pre-push hook, installed per clone
└── .github\ci\  check_repo_invariants.py   the wiring checks CI runs
```

Test comments here carry the **evidence** for why a test exists — the finding, the commit,
the measured failure. Preserve it when editing; the file header is often the only record.

`CLAUDE.md` holds the same ground in more operational detail, including the port
allocations and the per-harness history.

## License

Copyright © 2026 Khrustal & Mann, MELBOURNE, VICTORIA, AUSTRALIA, 3000.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text
and [NOTICE](NOTICE) for what it covers.
