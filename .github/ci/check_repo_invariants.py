#!/usr/bin/env python3
# Copyright © 2026 Khrustal & Mann
#              MELBOURNE, VICTORIA, AUSTRALIA, 3000
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
"""
check_repo_invariants.py -- the checks this repository can make about itself
without a compiler and without its sibling repositories.

READ THIS BEFORE TRUSTING A GREEN RUN. This script does not build anything and
does not run a single test. MscsUnitTests holds the entire test suite for the
MSCS solution, and that suite cannot be built here: three of its dependencies
(Platform, P2PeerUtilityHubs, DspChain) have no git remote anywhere, and TreeFs
is on a private non-GitHub host. Every ctest figure the project's evidence rests
on is produced by hand on a developer machine.

So what is the point? Every check below exists because the corresponding defect
has ALREADY SHIPPED in this repository at least once, and each one was found
late, by a human, after the fact:

  * a suite that was called but not compiled in, dark for 14 days (a5e9195);
  * a DLL hand-copied next to the test exes, silently shadowing the one ctest
    had just built, so a fix could be "verified" green without being loaded;
  * nine tests deleted with the code they covered and not restored when the
    code came back, so a closed security finding quietly became an unverified
    claim for two days.

These are bookkeeping failures, and bookkeeping is exactly what a compiler-free
job can police. Nothing here substitutes for running the suite.

Exit 0 = all invariants hold. Exit 1 = at least one is broken.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Source files that are deliberately NOT wired into this repository's
# CMakeLists.txt. Each needs a reason, and the reason is checked in both
# directions: an entry that becomes wired is an error too, so this list cannot
# quietly rot into an excuse list.
KNOWN_UNWIRED = {
    "crypto_kat.cpp":
        "Registered by the SIBLING repo: TargetCore/CMakeLists.txt builds it "
        "from ../MscsUnitTests/crypto_kat.cpp, because it links -lcrypto only "
        "and needs none of this directory's harness.",
    "stdafx.cpp":
        "The MSBuild precompiled-header source (<PrecompiledHeader>Create). It is "
        "named by MscsUnitTests(2022).vcxproj and by MscsUnitTestsExternal's, "
        "never by CMake, which builds these targets without a PCH. Unreferenced "
        "here is correct; unreferenced by BOTH .vcxproj files would not be, and "
        "the suite-wiring job is what would notice that.",
    # dsp_wav_roundtrip.cpp was here as a recorded orphan (its own .vcxproj, in
    # no CMakeLists and no .sln). It moved to MscsUnitTestsExternal with the rest
    # of the DSP harnesses on 2026-08-14, so the entry went with it -- the orphan
    # is still an orphan, it is just no longer this directory's.
}

_errors = []
_notes = []


def fail(check, msg):
    _errors.append("[%s] %s" % (check, msg))


def note(msg):
    _notes.append(msg)


def read(path):
    with open(os.path.join(REPO, path), "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# NOT CHECKED HERE: duplicate add_test names.
#
# It was, in the first draft, and the check was wrong. alex_test is registered
# in both arms of an if(WIN32)/else() -- powershell on one side, bash on the
# other -- and a regex sees two registrations of one name where CMake sees one
# branch taken. Making the regex branch-aware would be reimplementing CMake's
# parser badly.
#
# CMake already enforces this natively: a genuine duplicate is a hard error at
# generate time ("add_test given test NAME which already exists"). The
# cmake-parse job runs generate, so the invariant IS enforced -- by the tool
# that understands the language. Left here as a note rather than deleted,
# because the obvious "improvement" is to add it back.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 1. Every source named literally in add_executable() exists on disk.
#
# CMake catches this at generate time, so the parse-check job would too -- but
# only for the branch that generator takes. This runs over the whole file, WIN32
# branch included, which the Linux parse-check never evaluates.
# ---------------------------------------------------------------------------
def check_named_sources_exist(cml):
    checked = 0
    for block in re.findall(r"add_executable\s*\(([^)]*)\)", cml, re.S):
        for tok in re.findall(r"[A-Za-z0-9_./${}-]+\.cpp", block):
            if "${" in tok:       # ${name}.cpp inside a foreach -- covered by check 2
                continue
            checked += 1
            if not os.path.isfile(os.path.join(REPO, tok)):
                fail("sources", "add_executable names %s, which is not on disk" % tok)
    note("%d literally-named add_executable sources all present" % checked)


# ---------------------------------------------------------------------------
# 2. Every .cpp in the repository root is wired into the build, or is listed
#    above with a reason.
#
# The check is a token match rather than a filename match, because tests are
# declared two ways here: `add_executable(p2p_authgate p2p_authgate.cpp)` and
# `foreach(name a b c) add_executable(${name} ${name}.cpp)`. Matching the stem
# as a whole word covers both.
#
# This is the check that would have caught the C-ABI restore: p2p_u8_smoke.cpp
# came back into the tree while its add_test entry did not.
# ---------------------------------------------------------------------------
def check_every_source_is_wired(cml):
    wired, unwired = 0, []
    # A KNOWN_UNWIRED entry for a file that no longer exists is never visited by
    # the loop below, so it would sit here forever describing nothing. That is
    # exactly how an allowlist rots into folklore -- fail on it.
    for entry in sorted(KNOWN_UNWIRED):
        if not os.path.isfile(os.path.join(REPO, entry)):
            fail("wiring", "%s is in KNOWN_UNWIRED but is not in this directory "
                           "any more -- delete the entry (it moved or was removed)"
                           % entry)
    for entry in sorted(os.listdir(REPO)):
        if not entry.endswith(".cpp"):
            continue
        stem = entry[:-4]
        if re.search(r"(^|[^A-Za-z0-9_])" + re.escape(stem) + r"([^A-Za-z0-9_]|$)", cml):
            if entry in KNOWN_UNWIRED:
                fail("wiring", "%s is in KNOWN_UNWIRED but IS now referenced by "
                               "CMakeLists.txt -- delete the entry, the exception "
                               "has been resolved" % entry)
            wired += 1
        elif entry in KNOWN_UNWIRED:
            unwired.append(entry)
        else:
            fail("wiring", "%s is in the repository but nothing in CMakeLists.txt "
                           "refers to it. Register it, or add it to KNOWN_UNWIRED "
                           "with a reason." % entry)
    note("%d sources wired into CMakeLists.txt; %d deliberately not (%s)"
         % (wired, len(unwired), ", ".join(unwired) or "none"))


# ---------------------------------------------------------------------------
# 3. No POST_BUILD step that copies a library next to the test executables.
#
# On 2026-08-13 two hand-copied DLLs were found sitting in the test exes' output
# directory. Windows searches the application directory BEFORE PATH, so they won
# over the loader path CMakeLists.txt sets up, and every test in the directory
# silently ran against a stale binary -- a fix could be verified green without
# ever having been loaded. Nothing in CMake had put them there.
#
# The obvious "fix" is a POST_BUILD copy step, which reinstates precisely that
# hazard with the build system's blessing. The comment in CMakeLists.txt says
# not to add one; this makes the comment enforceable.
# ---------------------------------------------------------------------------
def check_no_post_build_copy(cml):
    for m in re.finditer(r"POST_BUILD", cml):
        line_no = cml.count("\n", 0, m.start()) + 1
        # The standing warning in the file is prose, not a command.
        line = cml.splitlines()[line_no - 1].lstrip()
        if line.startswith("#"):
            continue
        fail("post-build", "CMakeLists.txt:%d introduces a POST_BUILD step. If it "
                           "copies a library beside the test exes it recreates the "
                           "stale-DLL hazard; see the comment in that file." % line_no)
    note("no POST_BUILD copy step (the stale-DLL hazard stays closed)")


# ---------------------------------------------------------------------------
# 4. golden_ref.p2p is still protected from end-of-line translation.
#
# It is a serialised P2Pmsg heap image and the byte-identical cross-OS reference
# that golden_utf16_bytes compares against. If .gitattributes stops marking it
# binary, checkout on Windows rewrites LF to CRLF inside a binary file and the
# guard fails for a reason that has nothing to do with the code under test.
# ---------------------------------------------------------------------------
def check_gitattributes_binary():
    ga = read(".gitattributes")
    if not re.search(r"^\s*\*\.p2p\s+binary\s*$", ga, re.M):
        fail("gitattributes", "'*.p2p binary' is no longer in .gitattributes; "
                              "golden_ref.p2p would be EOL-translated on checkout")
    else:
        note("golden_ref.p2p is still marked binary")


# ---------------------------------------------------------------------------
# 5. The pre-push hook is present and checked out with LF endings.
#
# It is a /bin/sh script. Checked out CRLF it fails with "bad interpreter", and
# a hook that cannot run is a hook that silently permits everything -- the
# failure mode is indistinguishable from success.
# ---------------------------------------------------------------------------
def check_hook_intact():
    hook = os.path.join(REPO, "tools", "hooks", "pre-push")
    if not os.path.isfile(hook):
        fail("hook", "tools/hooks/pre-push is missing")
        return
    with open(hook, "rb") as fh:
        blob = fh.read()
    if b"\r\n" in blob:
        fail("hook", "tools/hooks/pre-push contains CRLF; it will fail with "
                     "'bad interpreter' and silently permit every push")
    ga = read(".gitattributes")
    if not re.search(r"^\s*tools/hooks/\*\s+text\s+eol=lf\s*$", ga, re.M):
        fail("gitattributes", "'tools/hooks/* text eol=lf' is missing, so the hook "
                              "can be checked out CRLF on Windows")
    note("pre-push hook present, LF, and pinned to LF by .gitattributes")


# ---------------------------------------------------------------------------
# 6. Every `security`-labelled test DECLARES the verdict it expects.
#
# The gate tests encode a REQUIREMENT rather than the current behaviour, so a
# red one is the finding and not a broken test -- which is why WILL_FAIL is
# banned here. That rule only works if a reader can tell "expected red" from
# "regression", and on 2026-08-14 seven banners could not be told apart from
# either: they still announced *** EXPECTED TO FAIL *** for fixes that had
# landed weeks earlier in the sibling repositories, while ctest reported 22/22.
# The banners drifted precisely because nothing could contradict them.
#
# This makes the expectation MACHINE-READABLE. It does not, and cannot, verify
# it: see check_declared_status_matches_run() below for the half that does, and
# note that the half CANNOT run in CI here -- no compiler, no siblings, no test
# execution. What this check buys is that there is always something concrete for
# a real run to disagree with.
# ---------------------------------------------------------------------------
STATUS_RE = re.compile(r"^\s*#\s*STATUS:\s*(PASSES|EXPECTED-FAIL)\b", re.M)


def _security_tests(cml):
    """name -> banner text, for every test labelled `security`."""
    labelled = set(re.findall(
        r"set_tests_properties\s*\(\s*(\w+)[^)]*LABELS[^)]*\bsecurity\b", cml, re.S))
    # Each banner is the text between the previous add_executable() and this
    # one, so a target's banner can never absorb the target above it.
    marks = [(m.group(1), m.start())
             for m in re.finditer(r"add_executable\s*\(\s*(\w+)", cml)]
    banners = {}
    for i, (name, pos) in enumerate(marks):
        start = marks[i - 1][1] if i else 0
        banners.setdefault(name, cml[start:pos])
    return {n: banners[n] for n in sorted(labelled) if n in banners}, labelled


def check_security_tests_declare_status(cml):
    tests, labelled = _security_tests(cml)
    missing = [n for n in labelled if n not in tests]
    if missing:
        fail("status", "no add_executable() found for security test(s): %s"
                       % ", ".join(sorted(missing)))
    declared = {}
    for name, banner in tests.items():
        found = STATUS_RE.findall(banner)
        if not found:
            fail("status", "%s is labelled `security` but its banner declares no "
                           "STATUS. Add a line '#   STATUS: PASSES' or "
                           "'#   STATUS: EXPECTED-FAIL' above its add_executable(), "
                           "so a ctest run has something to contradict." % name)
        elif len(found) > 1:
            fail("status", "%s declares STATUS %d times (%s); exactly one is "
                           "expected." % (name, len(found), ", ".join(found)))
        else:
            declared[name] = found[0]
    if declared:
        note("%d security test(s) declare a STATUS (%d PASSES, %d EXPECTED-FAIL)"
             % (len(declared),
                sum(1 for v in declared.values() if v == "PASSES"),
                sum(1 for v in declared.values() if v == "EXPECTED-FAIL")))
    return declared


# ---------------------------------------------------------------------------
# The half CI cannot run: compare the declared STATUS against a REAL ctest run.
#
#     ctest --test-dir <build> -C Debug --output-junit results.xml
#     python check_repo_invariants.py --ctest-junit results.xml
#
# It is opt-in and developer-side on purpose. This repository's suite cannot be
# built on a runner at all (three dependencies have no remote), so every ctest
# figure it quotes comes from a developer's machine -- and this is the step that
# turns such a run into a check on the documentation instead of a number that
# gets pasted into a commit message and then goes stale.
#
# A declared EXPECTED-FAIL that PASSES is not a success to be quietly enjoyed:
# it means somebody fixed the finding and the banner still calls it open, which
# is the drift this whole section exists to catch.
# ---------------------------------------------------------------------------
def check_declared_status_matches_run(declared, junit_path):
    import xml.etree.ElementTree as ET
    try:
        root = ET.parse(junit_path).getroot()
    except Exception as exc:                       # noqa: BLE001 - reported, not raised
        fail("status-run", "cannot read ctest JUnit XML %s: %s" % (junit_path, exc))
        return
    actual = {}
    for tc in root.iter("testcase"):
        name = tc.get("name")
        if not name:
            continue
        bad = (tc.find("failure") is not None or tc.find("error") is not None
               or tc.get("status") in ("fail", "failed", "error"))
        actual[name] = "EXPECTED-FAIL" if bad else "PASSES"
    if not actual:
        fail("status-run", "%s contained no <testcase> elements" % junit_path)
        return
    matched, unseen = 0, []
    for name, want in sorted(declared.items()):
        got = actual.get(name)
        if got is None:
            unseen.append(name)
            continue
        if got == want:
            matched += 1
        else:
            if want == "EXPECTED-FAIL":
                fail("status-run", "%s declares STATUS: EXPECTED-FAIL but the run "
                                   "PASSED. The finding was fixed -- update the "
                                   "banner to STATUS: PASSES and say what closed "
                                   "it, or the next reader will treat a closed "
                                   "hole as open." % name)
            else:
                fail("status-run", "%s declares STATUS: PASSES but the run FAILED. "
                                   "Either it is a regression, or the banner was "
                                   "optimistic; do not 'fix' it by relaxing the "
                                   "assertion." % name)
    if unseen:
        note("%d declared test(s) absent from this run (%s) -- platform-gated, "
             "or the run was filtered" % (len(unseen), ", ".join(unseen)))
    note("%d declared STATUS(es) matched the ctest run in %s"
         % (matched, os.path.basename(junit_path)))


def main():
    junit = None
    argv = sys.argv[1:]
    if argv:
        if argv[0] == "--ctest-junit" and len(argv) == 2:
            junit = argv[1]
        else:
            print(__doc__)
            print("usage: check_repo_invariants.py [--ctest-junit <results.xml>]")
            return 2

    cml = read("CMakeLists.txt")

    check_named_sources_exist(cml)
    check_every_source_is_wired(cml)
    check_no_post_build_copy(cml)
    check_gitattributes_binary()
    check_hook_intact()
    declared = check_security_tests_declare_status(cml)
    if junit:
        check_declared_status_matches_run(declared, junit)
    else:
        note("STATUS declarations NOT compared against a run (pass "
             "--ctest-junit to do that; CI here cannot, it builds nothing)")

    for n in _notes:
        print("  ok   %s" % n)

    if _errors:
        print("")
        for e in _errors:
            print("  FAIL %s" % e)
        print("\n%d invariant(s) broken." % len(_errors))
        return 1

    print("\nAll invariants hold. This says nothing about whether the suite passes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
