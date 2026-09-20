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
# MscsUnitTests/CMakeLists.txt — regression-pin (LinuxPortPlan.md §9) for BOTH toolchains.
#
# Turns the hand-built runtime harnesses into CTest-registered regression tests so `ctest`
# gates them on each build. As of the CMake-on-Windows parity work (§7) this configures on
# Windows/MSVC too: it builds the PORTABLE suites (the algorithmic unit_suite, the UTF-8 _u8
# smokes, the P2PeerService daemon harness, and the UTF-16 golden) under CMake+MSVC, and
# guards the Linux-transport mesh harnesses (dmx/wsa/pipe/232/mix, which drive io_uring +
# PTYs) and the bash-script gates (golden_utf16_bytes / alex_test) to Linux. On Windows the
# authoritative full suite is still the (2026).vcxproj TestMain runner until this path signs off.
#
# Verdict for every harness = process EXIT CODE: 0 SUCCESS; non-zero = CTest failure.

# The portable suites include the legacy MFC headers (P2Pmsg.h / P2PeerHub.h) and link the
# Msgcore/Targetcore MFC extension DLLs, so the test exes must use shared MFC too on Windows.
# CMAKE_MFC_FLAG is consumed at add_executable() time, so set it before any target here.
if(WIN32)
    set(CMAKE_MFC_FLAG 2)
endif()

# A component that is absent degrades unit_suite to a smaller runner. It still
# BUILDS -- a partial checkout is not a configure error by default -- but it does
# not PASS: the runner reports INCOMPLETE and exits 2, so the test fails.
# UtilHubsSuite.cpp was missing from the Windows .vcxproj for 14 days
# (a5e9195 -> f7f7d72) and nobody noticed, because a dropped suite looked exactly
# like a passing run; a reduced run is now never green.
#
# So a missing component surfaces three ways: a configure-time warning here, a
# SKIPPED line plus exit 2 from the runner, and -- with this option ON -- a hard
# configure error, which is what you want in CI where a late failure is expensive.
option(MSCS_STRICT_SUITES
       "Fail configuration (not just the test) if a suite would be skipped" OFF)

# The include surface, the compile shape (_mscs_test_common) and the runtime
# loader path (_mscs_apply_loader_path) are SHARED with MscsUnitTestsExternal.
# One copy, included by both — see that file's header for why.
include(${CMAKE_CURRENT_SOURCE_DIR}/MscsTestCommon.cmake)

# ---------------------------------------------------------------------------
# Portable suites — built + gated on BOTH platforms.
# ---------------------------------------------------------------------------

# unit_suite: the algorithmic unit runner (TestMain.cpp) for the two libraries this
# directory is named for — the Msgcore data-structure suite, the Msgcore C-API suite
# and the Targetcore suite. 119 cases.
#
# The TreeFS core/actor/posix/service, replication, blob and P2PeerUtilityHubs suites
# were here until 2026-08-14 and are now MscsUnitTestsExternal's unit_suite_external.
# The consequence is the point of the split: this target links msgcore, targetcore and
# p2pplatform and NOTHING else — no treefs, no p2putilhubs — so it can be built from
# the two repositories that are actually published.
#
# TestFramework.cpp carries the runner lifecycle and is shared with the external
# runner.
#
# This target depends on NO component outside the published repositories. It used to
# reach into MsgcoreMFC/ on Windows to compile two translation units for the COleTime
# DATE helpers, and to substitute an identity-function shim for them on Linux. Both
# are gone -- see the Test_DateNormalisation note in MsgcoreSuite.cpp for why the
# cases went with them.
add_executable(unit_suite
    TestMain.cpp
    TestFramework.cpp
    MsgcoreSuite.cpp
    MsgcoreCApiSuite.cpp
    TargetcoreSuite.cpp)
_mscs_test_common(unit_suite)
target_link_libraries(unit_suite PRIVATE targetcore msgcore p2pplatform)
add_test(NAME unit_suite COMMAND unit_suite)
set_tests_properties(unit_suite PROPERTIES TIMEOUT 60)

# msgcore_u8_smoke / p2p_u8_smoke: the UTF-8 (_u8) C-API round-trips (§6). Prove a UTF-8
# string (1/2/3/4-byte incl. astral U+1F680) round-trips name+value byte-identically — the
# cross-platform-FFI guarantee (the same exe produces identical bytes on both OSes).
#
# p2p_u8_smoke was removed with Targetcore's flat C API and RESTORED with it on 2026-08-14:
# Targetcore_c.* is back in the tree (74 exported entry points) and is what
# MSCS_JavaBindings downcalls into. Between the two events the _u8 transcoding half of that
# ABI was shipped with no test on either platform. If the ABI goes away again, this goes
# with it — and comes back when it does.
add_executable(msgcore_u8_smoke msgcore_u8_smoke.cpp)
_mscs_test_common(msgcore_u8_smoke)
target_link_libraries(msgcore_u8_smoke PRIVATE msgcore p2pplatform)
add_test(NAME msgcore_u8_smoke COMMAND msgcore_u8_smoke)

add_executable(p2p_u8_smoke p2p_u8_smoke.cpp)
_mscs_test_common(p2p_u8_smoke)
target_link_libraries(p2p_u8_smoke PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_u8_smoke COMMAND p2p_u8_smoke)

# p2p_daemon_harness: P2PeerService daemon runtime lifecycle (§6.2) — construct the service,
# post a hub, SpawnHub, stop via OnStop, CloseHub. Native IOCP on Windows / io_uring on Linux.
add_executable(p2p_daemon_harness p2p_daemon_harness.cpp)
_mscs_test_common(p2p_daemon_harness)
target_link_libraries(p2p_daemon_harness PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_daemon_harness COMMAND p2p_daemon_harness)

# golden_utf16: UTF-16 pinning round-trip (§4.2). Needs only msgcore; takes a save path.
# A Windows-built and a Linux-built golden_utf16 produce a bit-identical image (the cross-OS
# byte-identity is asserted by golden_utf16_bytes on Linux).
add_executable(golden_utf16 golden_utf16.cpp)
_mscs_test_common(golden_utf16)
target_link_libraries(golden_utf16 PRIVATE msgcore p2pplatform)
add_test(NAME golden_utf16 COMMAND golden_utf16 ${CMAKE_CURRENT_BINARY_DIR}/golden.p2p)

# golden_utf16_bytes: CROSS-OS byte-identity guard (§4.2) — regenerate the image and compare
# it byte-for-byte with the checked-in golden_ref.p2p, so any serialised heap-format drift on
# EITHER toolchain fails ctest. Uses a portable `cmake -P` driver (cmake -E compare_files) so
# it gates on Windows too — asserting the Windows-built golden matches the reference bit-for-bit.
add_test(NAME golden_utf16_bytes COMMAND ${CMAKE_COMMAND}
    -DGOLDEN_EXE=$<TARGET_FILE:golden_utf16>
    -DOUT_IMG=${CMAKE_CURRENT_BINARY_DIR}/golden_check.p2p
    -DREF_IMG=${CMAKE_CURRENT_SOURCE_DIR}/golden_ref.p2p
    -P ${CMAKE_CURRENT_SOURCE_DIR}/golden_bytes_check.cmake)

# ---------------------------------------------------------------------------
# Transport mesh harnesses. Each drives the full targetcore transport stack; the transports
# are platform-native under the hood (loopback TCP over io_uring on Linux / Winsock IOCP on
# Windows; AF_UNIX on Linux / named pipes on Windows; in-process Dmx everywhere), and the
# harness .cpp files are portable, so the TCP/pipe/Dmx meshes gate on BOTH toolchains now.
# ---------------------------------------------------------------------------
# A Targetcore runtime harness: one TU, links the full transport stack, verdict = exit code.
function(mscs_mesh_test name)
    add_executable(${name} ${name}.cpp)
    _mscs_test_common(${name})
    target_link_libraries(${name} PRIVATE targetcore msgcore p2pplatform)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

mscs_mesh_test(dmx_mesh)      # in-process Dmx pump + login (no OS handle)
mscs_mesh_test(wsa_mesh)      # loopback TCP (io_uring on Linux / Winsock IOCP on Windows)
mscs_mesh_test(pipe_mesh)     # AF_UNIX (Linux) / named pipe (Windows)
mscs_mesh_test(mix_con)       # one hub, Wsa + Pipe cons at once (Phase-4 exit)
mscs_mesh_test(mix_con3)      # + Dmx: the TOCTOU-stall reproduction (run repeatedly)
set_tests_properties(mix_con3 PROPERTIES TIMEOUT 60)

# alex_test: the two-PROCESS cross-process TCP proof (§9) — a separate server + client process
# (not the in-process meshes), over io_uring on Linux / Winsock IOCP on Windows. The exe is a
# mode-arg server/client; a launcher spawns both and asserts both exit 0. The orchestration is
# bash on Linux and a PowerShell twin on Windows (same steps: start server, run client, reap).
add_executable(alex_test alex_test.cpp)
_mscs_test_common(alex_test)
target_link_libraries(alex_test PRIVATE targetcore msgcore p2pplatform)
if(WIN32)
    add_test(NAME alex_test COMMAND powershell -NoProfile -ExecutionPolicy Bypass
        -File ${CMAKE_CURRENT_SOURCE_DIR}/run_alex_test.ps1 $<TARGET_FILE:alex_test> 7811)
else()
    add_test(NAME alex_test COMMAND bash
        ${CMAKE_CURRENT_SOURCE_DIR}/run_alex_test.sh $<TARGET_FILE:alex_test> 7811)
endif()
set_tests_properties(alex_test PROPERTIES TIMEOUT 60 RESOURCE_LOCK loopback_7811)

# ---------------------------------------------------------------------------
# p2p_authgate: SECURITY gate test for SECURITY_REVIEW finding H6 ("no
# authentication gate in message dispatch"). Stands up a stock hub, then opens
# a RAW TCP socket — no P2PeerCon, no login, no key exchange — and writes one
# library-serialized frame. Asserts the handler does NOT run.
#
#   *** PASSES (measured 2026-08-14). Regression guard, not an open finding. ***
#
# It was written expecting to FAIL and did not. H6 was closed by c62613a ("Gate
# application-message dispatch behind login", 2026-07-05); the gate is the
# `else if ( (m_dwState & ConState_Login) )` at P2PeerCon.cpp:403 and nothing
# else in the tree enforces it, so it is one refactor from silently vanishing.
#
# It still encodes the requirement rather than the behaviour, which is why it
# keeps its value now that it is green. Do not add WILL_FAIL: that would make
# CI green on an open security hole and then "fail" the day it is fixed.
# Labelled `security` so a known-state run can exclude it deliberately:
#   ctest -LE security      # everything except the known-red gate tests
#   ctest -L  security      # just the gate tests
#
# A PASS here is only meaningful if the positive controls (wsa_mesh, alex_test)
# are green in the same run — a hub that dispatches nothing would also pass.
#   STATUS: PASSES        (measured 2026-08-14, Windows Debug)
add_executable(p2p_authgate p2p_authgate.cpp)
_mscs_test_common(p2p_authgate)
target_link_libraries(p2p_authgate PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_authgate COMMAND p2p_authgate 7813)
set_tests_properties(p2p_authgate PROPERTIES
    TIMEOUT 60 RESOURCE_LOCK loopback_7813 LABELS security)

# p2p_authspoof: the gate p2p_authgate does NOT cover. Passing the login gate
# only requires COMPLETING a login, and the login proves no identity — the
# claimed address is accepted as-is whenever no P2Padomain is configured
# (P2PeerCon.cpp:1887-1896), and routing then reads the source from the MESSAGE
# (P2PeerCon.cpp:412) rather than from m_oThatP2Paddr. A legitimately logged-in
# peer can therefore attribute its traffic to any identity it likes.
# SECURITY_REVIEW M2; the substance of what remains of H6 after c62613a.
#
#   *** PASSES (measured 2026-08-14). Source binding landed at
#       P2PeerCon.cpp:403+, which binds the message source to the logged-in
#       identity; this is now the regression guard for that fix. ***
#
# Same rules as above: no WILL_FAIL, labelled `security`. Note this test treats
# TIMEOUT as inconclusive (exit 3), not as a pass.
#   STATUS: PASSES        (measured 2026-08-14, Windows Debug)
add_executable(p2p_authspoof p2p_authspoof.cpp)
_mscs_test_common(p2p_authspoof)
target_link_libraries(p2p_authspoof PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_authspoof COMMAND p2p_authspoof 7814)
set_tests_properties(p2p_authspoof PROPERTIES
    TIMEOUT 60 RESOURCE_LOCK loopback_7814 LABELS security)

# p2p_authancestor: the ONE documented exemption from the rule authspoof
# guards. A link to a peer at or ABOVE this hub carried no source check at all,
# because a message routed DOWN from a parent legitimately carries a source
# from another branch - outside the relaying peer's subtree, so the descendant
# test refuses it, and downward transit stops working. The address alone cannot
# tell that apart from the parent inventing the source.
#
# It exists because removing the exemption left the suite at 38/38. Every other
# multi-hub topology here routes through a COMMON ancestor (sealhop is
# Seal.Alice -> Seal -> Seal.Carol), so the source is always at-or-below the
# peer and the descendant test admits it before the exemption is reached. This
# is still the only test that puts a source OUTSIDE the relaying ancestor's
# subtree.
#
# UNTIL 2026-08-14 IT ASSERTED THAT GAP - the only test here that asserted the
# absence of a protection rather than its presence. The exemption became
# closable with RequireRelayAuth(true), which binds the source to the identity
# that SIGNED the message instead of to the peer that DELIVERED it, so it began
# asserting the protection instead - while one phase still pinned the old
# behaviour as the DEFAULT, because closing it was opt-in.
#
# ON 2026-08-18 (ProductionPlan.md Stage 3 step 9) CLOSING IT BECAME THE
# DEFAULT, and the phases reordered around that. Nothing in the test turns
# RequireRelayAuth on any more; the phases that need it ASSERT it is already
# true, so a reverted default fails as SETUP rather than passing for the wrong
# reason. Phase 2 relays a genuinely attested cross-branch message DOWN through
# two KEYLESS hubs with no switch set anywhere, and it must arrive. Phase 3 is
# the migration - RequireRelayAuth(false) at the leaf restores the old exemption
# exactly - and it does double duty, because it shows the identical message on
# the identical connection arriving when and only when the switch is off, which
# is what makes phase 4's refusal attributable. Phase 4 is the forgery, back on
# the default, and must be refused.
#
# The order is not arbitrary: a refusal DROPS THE CONNECTION, so the two phases
# that must arrive have to run before the one that must not.
#
# Four hubs and TWO ports, and both are necessary: for a message to reach a hub
# from outside its parent's subtree HONESTLY, the parent must itself have got it
# from ITS parent, so the shortest real topology is four levels deep. The
# previous version could not build that shape and simulated it by having the
# parent claim a foreign source - fine while nothing was checked, useless now.
#   STATUS: PASSES        (measured 2026-08-18, Windows Debug + Linux,
#                          on DEFAULT configuration)
add_executable(p2p_authancestor p2p_authancestor.cpp)
_mscs_test_common(p2p_authancestor)
target_link_libraries(p2p_authancestor PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_authancestor COMMAND p2p_authancestor 7820)
# BOTH locks: the test binds the port it is given AND the next one, for the
# interior hub that is a client of its parent and a service to its child.
set_tests_properties(p2p_authancestor PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK "loopback_7820;loopback_7821" LABELS security)

# p2p_bigreport: the undeliverable report that cannot be delivered either.
# RouteP2PeerMsg answers an undeliverable message with an exception that EMBEDS
# the whole message, so the report is always bigger than what it reports on -
# and nothing checked it against either of the two limits above it. Measured on
# a 30000-byte message (a stock peer may send 32768): the report was built in a
# 16-bit message heap and THREW at 65561 with no report sent; and once that was
# bounded, a report still over 32768 was refused by the receiver at 38424 bytes
# and the connection dropped. Either way the sender is never told.
#
# Session 31 capped the report CASCADE (an undeliverable exception is dropped
# rather than answered with another one). This needs no cascade: one message,
# one lap. Its own note recorded it as still open.
#
# THIS TEST IS THE ONLY GUARD ON THE SECOND LIMIT. The unit-suite cases cover
# the heap one; nothing else in the tree covers the receive-size one, which is
# why this test outlives the fix that made it green.
#
#   *** PASSES (measured 2026-08-14), where it was previously the sole red. ***
#
# Stage 1 is an inline positive control at 64 bytes, so a silence in stage 2
# cannot be confused with a broken transport or a routable ghost address.
# Stage 3 re-sends the control afterwards, which is what distinguishes a lost
# report from a hub that has stopped routing for everyone.
#   STATUS: PASSES        (measured 2026-08-14, Windows Debug)
add_executable(p2p_bigreport p2p_bigreport.cpp)
_mscs_test_common(p2p_bigreport)
target_link_libraries(p2p_bigreport PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_bigreport COMMAND p2p_bigreport 7823)
set_tests_properties(p2p_bigreport PROPERTIES
    TIMEOUT 90 RESOURCE_LOCK loopback_7823 LABELS security)

# p2p_reportsign: F-S9-1 - the undeliverable report, and the exemption it used
# to need. GateRelayInbound refuses a source nobody has attested for, and the
# library's OWN report could never satisfy it: WrappedResponseFactory SWAPS the
# addresses, so the report was sourced from the address that could not be
# reached. A report for 'Ghost.Nowhere' declares a source in no branch at all
# and carries no attestation, because nobody holds a key for an address that
# does not exist - byte-for-byte the shape the gate refuses. So the gate
# exempted P2Pmsg_Exception BY CLASS, and a peer on an ancestor link could then
# forge a report against ANY source.
#
# CLOSED AT THE SOURCE, NOT AT THE GATE. RouteP2PeerMsg stamps the report with
# the address of the hub that RAISED it, which that hub can speak for; the class
# exemption is gone.
#
# THREE HUBS, and two would prove only the easy half: one hop below the
# reporting hub the plain descendant test admits the report and the attestation
# path is never entered, so a green run would say nothing about signing. The
# KEYLESS relay in the middle is what forces the report through
# GateRelayInbound, which is the branch the finding lived in. Rep holds the only
# identity in the topology - the claim in one line.
#
# Phase 3 replays the PRE-FIX report shape from a hub not entitled to it, built
# by ExceptionFactory rather than hand-assembled, so what is refused is exactly
# what the exemption used to admit. It runs last because a refusal drops the
# connection.
#   STATUS: PASSES        (measured 2026-08-20, Windows Debug + Release, Linux,
#                          and Linux ASan+UBSan+LSan with detect_leaks=1)
#           Proven RED in both directions before it was believed: with the stamp
#           removed it exits 4 (the report is refused at the first relay hop and
#           the sender is never told); with the class exemption restored it exits
#           1 (a relay's forged report sourced Ghost.Nowhere is admitted).
add_executable(p2p_reportsign p2p_reportsign.cpp)
_mscs_test_common(p2p_reportsign)
target_link_libraries(p2p_reportsign PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_reportsign COMMAND p2p_reportsign 7844)
# BOTH locks: the interior hub is a client of its parent AND a service to its
# child, so the test binds the port it is given and the next one.
set_tests_properties(p2p_reportsign PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK "loopback_7844;loopback_7845" LABELS security)

# p2p_authpsk: the third gate. authgate proves an unauthenticated peer cannot
# reach a handler; authspoof proves a logged-in peer cannot forge its source.
# Together they make every message attributable to the identity its connection
# logged in as - and say nothing about whether that identity is REAL. OnLogin
# installs the claimed address straight off the wire, and the P2Padomain check
# above it is skipped when no domain is configured (the stock default). So a
# peer simply logs in AS whoever it wants and is self-consistent thereafter.
#
#   *** PASSES (measured 2026-08-14). The signed login landed
#       (Targetcore/P2PAuthLogin.h), so the claimed identity is now PROVEN and
#       not merely asserted. Measured verdict: "Both peers matched the domain
#       'AuthPsk.*'; only one matched a key." ***
#
# Same rules as above: no WILL_FAIL, labelled `security`, and phase 1 is an
# inline positive control so a refusal is distinguishable from a dead transport.
#   STATUS: PASSES        (measured 2026-08-14, Windows Debug)
add_executable(p2p_authpsk p2p_authpsk.cpp)
_mscs_test_common(p2p_authpsk)
target_link_libraries(p2p_authpsk PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_authpsk COMMAND p2p_authpsk 7815)
set_tests_properties(p2p_authpsk PROPERTIES
    TIMEOUT 60 RESOURCE_LOCK loopback_7815 LABELS security)

# p2p_armgate: ProductionPlan.md Stage 3 step 8 - RequireAuth(true) BY DEFAULT,
# and the arming gate that keeps the flip from being an outage.
#
# The default was off from the day the feature landed until 2026-08-18, which
# meant the deployments that most needed verification were exactly the ones that
# never called RequireAuth. Flipping it alone would have traded one silent
# failure for a later one: a hub that requires auth and holds no keys refuses
# EVERYONE, at the first peer's login, in production. So a hub that cannot
# enforce what it requires no longer starts - CreateHub() returns FALSE,
# SpawnHub() returns 0, and the refusal names the file that is missing.
#
# NO SOCKETS, so it needs no RESOURCE_LOCK and no port. Seven phases, of which
# two are controls that have to be there: phase 4 arms a fully provisioned hub
# (without it, every refusal is indistinguishable from a build where nothing
# arms) and phase 6 arms an unprovisioned one that said RequireAuth(false)
# (without it, the documented migration is untested and the change is an outage
# rather than a default).
#
# Phase 5 is the falsification the plan asks for by name: provision a hub, watch
# it arm, DELETE its allow-list, and watch the same hub refuse - reporting
# ArmAllowUnusable and still able to name the path it lost.
#
# TEN PHASES SINCE 2026-08-21 (Stage 3 step 19), because the gate grew a second
# question: RequireRevocation defaults to true, so a hub that requires auth must
# also hold a revocation POSITION. Phase 8 is the case that makes this a bigger
# break than step 8 - a hub with no revocation list REFUSES NOBODY and works,
# and is stopped anyway, because revocation is the only mechanism here for
# withdrawing trust already granted. Phase 9 is the RequireRevocation(false)
# migration, and it also asserts the opt-out is NARROW (auth still required).
# Phase 10 is the second falsification, in phase 5's shape: delete a CONFIGURED
# revocation list and watch ArmRevocationUnusable - distinct from
# ArmNoRevocation, naming the revocation file rather than the allow-list, and
# NOT escapable by the opt-out.
#
# Phases 4 and 5 changed with it: "fully provisioned" is three files now, not
# two. Without that the positive control would assert a state no deployment can
# reach.
#   STATUS: PASSES        (measured 2026-08-18, Windows Debug + Linux;
#           re-measured 2026-08-21 with the revocation phases, Windows Debug
#           + Release. The first run went red at phase 8 SETUP: phase 5
#           DELETES the allow-list on purpose, so every phase after it that
#           wants a provisioned hub needs a file that still exists. There is
#           a second allow-list now, and the lesson is that a falsification
#           phase which destroys shared state has to say so to its successors.)
add_executable(p2p_armgate p2p_armgate.cpp)
_mscs_test_common(p2p_armgate)
target_link_libraries(p2p_armgate PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_armgate COMMAND p2p_armgate)
set_tests_properties(p2p_armgate PROPERTIES
    TIMEOUT 60 LABELS security)

# p2p_sealdefault: ProductionPlan.md Stage 3 step 20 - the sealed body becomes
# a MULTI-RECIPIENT envelope (kSealVersion 1 -> 2) and sealing a relayed body
# becomes the default, refusing to send rather than downgrading to cleartext.
#
# The format had to change before the default was possible. v1 sealed to
# exactly one reader, so "seal by default" would have meant "break every
# deployment that needs an intermediate hub to read the body" - and that is a
# real shape: content routing, filtering, store-and-forward. v2 encrypts the
# body once and wraps the content key once per reader.
#
# Phase 2 is the new ability - a destination AND a hub the sender named both
# open the same block. Phase 3 is its limit: a party the sender did NOT name
# gets SealErrNotAReader, distinct from a tag failure, because a relay must
# tell "not for me" from "damaged" to know whether to forward. Phase 4 is the
# falsification - edit a reader slot and the named reader refuses on the
# SIGNATURE, which is what stops a relay splicing itself in. Phase 6 is the
# instruction the step was given, in one assertion: no success path that could
# be read as "sent it in clear".
#
# NO SOCKETS, so no RESOURCE_LOCK and no port.
#   STATUS: PASSES        (measured 2026-08-21, Windows Debug + Release)
add_executable(p2p_sealdefault p2p_sealdefault.cpp)
_mscs_test_common(p2p_sealdefault)
target_link_libraries(p2p_sealdefault PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_sealdefault COMMAND p2p_sealdefault)
set_tests_properties(p2p_sealdefault PROPERTIES
    TIMEOUT 60 LABELS security)

# p2p_keyrotate: the gate after authpsk. authpsk proves the identity a peer
# claims is REAL. This asks what happens when that identity's key has to
# CHANGE - which SECURITY.md's roadmap carried as unanswered for four sessions
# ("Key rotation and revocation - Not implemented, for either key kind").
#
# Two failures sat behind that line. FindPeer took the FIRST allow-list entry
# for an address, so a second key for a peer was dead weight and rotating meant
# a flag day across every server that trusts it. And there was no way to
# WITHDRAW a key at all, so a compromised peer stayed trusted until someone
# hand-edited every allow-list. The second is what makes the first safe:
# rotation on its own only ever adds trust.
#
#   *** PASSES (measured 2026-08-14). The allow-list now accepts several keys
#       per address and every one is tried, and a separate revocation list
#       overrides it - reloadable on a running hub, and fail-closed if it
#       cannot be read. ***
#
# Same rules as the gates above: no WILL_FAIL, labelled `security`, phase 1 is
# an inline positive control, and phase 4 is a LIVENESS control - without it a
# revoked key being refused is indistinguishable from a server that has fallen
# over, since both are silence.
#   STATUS: PASSES        (measured 2026-08-14, Windows Debug)
add_executable(p2p_keyrotate p2p_keyrotate.cpp)
_mscs_test_common(p2p_keyrotate)
target_link_libraries(p2p_keyrotate PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_keyrotate COMMAND p2p_keyrotate 7824)
set_tests_properties(p2p_keyrotate PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7824 LABELS security)

# p2p_authrelay: the fourth gate, and the one the signed login does NOT close.
# authpsk proves the peer is who it says it is. This asks the next question: is
# that proof bound to the CHANNEL it was made on? Today it is not - the
# signature covers the login MESSAGE (addresses, nonce, timestamp) and nothing
# about the transport, because on a cleartext wire with no key exchange there
# is nothing to bind to. So a plain TCP relay can forward a genuine login
# untouched and then speak in that peer's name, holding no key and forging
# nothing. Every existing check passes: the login it carried is fresh,
# single-use and correctly addressed.
#
#   *** PASSES (measured 2026-08-14). Both halves landed: P2PAuthLogin.h now
#       computes a 32-byte SHA-256 channel binding (AuthChannelBind /
#       kAuthBindLen) and FOLDS IT INTO THE SIGNED TRANSCRIPT, which is the
#       half that was easy to leave out. Measured verdict: "the injected frame
#       was not dispatched -- the carrier of its proof could not speak in its
#       name." ***
#
# The second half is the part easy to leave out - an authenticated login on an
# unauthenticated channel - and this test is what will notice if it is. Same
# rules as above: no WILL_FAIL, labelled `security`, phase 1 an inline positive
# control. It uses TWO ports: the relay listens on N, the server on N+1.
#   STATUS: PASSES        (measured 2026-08-14, Windows Debug)
add_executable(p2p_authrelay p2p_authrelay.cpp)
_mscs_test_common(p2p_authrelay)
target_link_libraries(p2p_authrelay PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_authrelay COMMAND p2p_authrelay 7816)
set_tests_properties(p2p_authrelay PROPERTIES
    TIMEOUT 60 RESOURCE_LOCK loopback_7816 LABELS security)

# p2p_sealhop: the gate none of the four above can close, because the party it
# is about is a LEGITIMATE one. An intermediate hub routes on the destination
# address (P2PeerHub.cpp:706), so it must be able to read the frame - a hub
# that could not read it could not forward it. The connection cypher protects
# one HOP, and the middle hub is the far end of the first one. Only sealing the
# BODY to the destination hides it from the carrier.
#
# Three real hubs over real sockets: Seal.Alice -> Seal -> Seal.Carol, with the
# middle observing everything it forwards through PeekP2PeerMsg and holding no
# keys of any kind. Auth is OFF on purpose - there is no session key and the
# link encrypts nothing, so a pass cannot be credited to hop crypto. Phase 1
# sends a marker in clear and REQUIRES the middle to see it, which is what
# makes phase 2's silence mean something.
#   STATUS: PASSES        (measured 2026-08-14, Windows Debug)
add_executable(p2p_sealhop p2p_sealhop.cpp)
_mscs_test_common(p2p_sealhop)
target_link_libraries(p2p_sealhop PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_sealhop COMMAND p2p_sealhop 7818)
set_tests_properties(p2p_sealhop PROPERTIES
    TIMEOUT 90 RESOURCE_LOCK loopback_7818 LABELS security)

# p2p_sealbcast: the automatic seal, over a real link, on the default policy.
#
# p2p_sealhop seals BY HAND over three hubs with RequireSeal(false).
# p2p_sealdefault exercises the default and the v2 envelope with NO SOCKETS.
# Nothing joined the two, and the gap was collective rather than chosen: every
# socket test here turns sealing off for its own good local reason
# (p2p_authancestor:422, p2p_bigreport:329, p2p_reportsign:502, p2p_sealhop:394),
# so SealAppMsgOutbound -> wire -> OpenAppMsgInbound had never run end to end on
# the configuration every deployment gets by default.
#
# Writing it found two defects that stopped any relayed message leaving the
# sender, both fixed 2026-08-24 and both guarded here:
#
#   Msgcore/P2Pmsg.cpp:983  P3PmsgData::c_vBlob could not grow a payload, which
#     is what writing a seal back over the body requires (+234 bytes). Under 256
#     bytes it refused to widen a BLOB08 and threw, taking the LINK down; over
#     255 it resized but handed NewVBLockData the blob size where c_memcpy hands
#     it VBLockData_Sizeof(...), under-allocating the descriptor and corrupting
#     the message heap. An ASSERT(0) at the top of the branch made it
#     unreachable in Debug, so it only ever ran where nothing checked it.
#     Phases 1 and 2 are the two size regimes and both must stay.
#
#   P2PeerCon.cpp:746  the send path attested BEFORE sealing, so the signature
#     covered the plaintext while the receiver - GateRelayInbound runs before
#     OpenAppMsgInbound - verifies the sealed bytes. "signature does not verify"
#     at the destination, and another dropped link. Now seal, then attest, which
#     is also encrypt-then-sign.
#
# A third defect, found by phase 3 and fixed 2026-08-25, is guarded by phase 4:
#
#   TMsg_Scp (P2PeerMsg.h)  a message carried ONE address where it needed two.
#     Dst means "where this is ultimately going" to a sender and "who this link
#     hands it to" to a router, and for a unicast those coincide - which is why
#     nothing noticed. On_P2PeerBCast sends a COPY PER LINK re-addressed to that
#     link's own peer (RedirectFactory), so from the first hop onward Dst named
#     the next hop and the origin's intent was gone. Two protections read it as
#     the first meaning and were silently wrong on every fanned-out copy: the
#     seal hook's last-hop exemption became true at EVERY hop (a broadcast
#     crossed a keyless carrier in clear), and AttestRelay digested an address
#     the fan-out then rewrote (the leaf answered "signature does not verify"
#     and dropped the link). One mechanism, two protections.
#     The scope is now stamped once by the hub that fans out, RedirectFactory
#     leaves it alone, and both ends of both checks read GetScopeOrDestin().
#     Absent - i.e. every unicast - falls back to Dst, so those paths are
#     unchanged and every other test here proves it.
#
# Phase 4 is the guard, and it is NOT vacuous: reverting AttestAppMsgOutbound
# alone to GetDestin reproduces "signature does not verify" plus a dropped link
# and turns phase 4 red. Measured 2026-08-25 before this was committed.
#
# GREEN SINCE 2026-08-25, AND ON WHAT. Phase 3 no longer leaks and no longer
# drops a link: the seal hook fires on a broadcast for the first time and
# REFUSES it, because a scope names a SUBTREE and no single agreement key opens
# one. Phase 5 then exercises RequireSealBroadcast(false) - the switch that lets
# a deployment record that its broadcasts are not confidential - and requires
# BOTH halves of it: the broadcast readable, AND the relayed unicast beside it
# still opaque. A switch that exempted everything would pass a test that only
# sent the first.
#
# READ THE GREEN CORRECTLY. Confidential broadcast is NOT available and is still
# an open design question (ProductionPlanLatest2.md item 6, three shapes
# analysed, none built). This test passes on the decision having been MADE - a
# broadcast is refused by default and exempt only when someone writes it down -
# not on the capability existing. The original defect was never that a broadcast
# went unencrypted; it was that the exemption was inherited from a re-addressing
# accident and nobody had chosen it.
#
# The negative checks were run rather than assumed, both on 2026-08-25 before
# this was committed:
#   revert AttestAppMsgOutbound alone to GetDestin  -> phase 4 red,
#     "signature does not verify" plus a dropped link;
#   drop the HasScope() test from the exemption     -> phase 5 red,
#     "PLAINTEXT - EXEMPTION LEAKED" on the unicast line.
#
# Same rules as the gate tests above: no WILL_FAIL - that would make CI green on
# an open hole and then "fail" the day it is closed - and labelled `security`.
# Exit 3 (inconclusive) is NOT a pass and ctest reads it as a failure.
#   STATUS: PASSES, all 5 phases.
#           (Windows Debug, Windows Release and Linux gcc/OpenSSL, all 2026-08-25
#            and all byte-identical.)
add_executable(p2p_sealbcast p2p_sealbcast.cpp)
_mscs_test_common(p2p_sealbcast)
target_link_libraries(p2p_sealbcast PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_sealbcast COMMAND p2p_sealbcast 7846)
set_tests_properties(p2p_sealbcast PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7846 LABELS security)

# p2p_acceptcap: the gate for the peer that says NOTHING. Every other gate here
# asks about a peer that has spoken - is its login real, is its source bound,
# can the middle read the body. Until 2026-08-16 nothing asked what an
# unauthenticated peer could simply HOLD: no accepted-connection count existed,
# so the bound was the descriptor table, and the login deadline - a timer that
# has been complete since the import, throwing "Login timed out" on expiry and
# cancelled in all three of the right places - was never armed, because the one
# SetPITimer call sat commented out in P2PeerTarget::On_ConAccept().
#
# Raw sockets rather than hubs, deliberately: the adversary being modelled does
# not run this library and will not complete a handshake, so the test must not
# either. Phase 1 is its own positive control (the two connections inside the
# cap must survive) and phase 2 carries a liveness control after the drop.
#
# TWO ctest entries out of one SOURCE, and the split is not tidiness. The CAP
# holds on both platforms. The LOGIN DEADLINE holds on Windows and is BROKEN ON
# LINUX: the drop that follows a timeout also cancels the listening socket's
# pending accept (995), the service reads that as an accept failure and drops
# itself, and one timed-out peer takes the whole listener down. It is therefore
# off by default (DEF_P2PeerConLogin) and its test is registered only where the
# feature works. Registering one test that quietly skipped its second half on
# Linux would be a green tick over a known hole, which is the one thing this
# suite is not for.
#   STATUS: PASSES        (measured 2026-08-16, Windows Debug + Release, Linux)
add_executable(p2p_acceptcap p2p_acceptcap.cpp)
_mscs_test_common(p2p_acceptcap)
target_link_libraries(p2p_acceptcap PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_acceptcap COMMAND p2p_acceptcap 7826 --cap-only)
set_tests_properties(p2p_acceptcap PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7826 LABELS security)

# p2p_servicedialog: the rule that keeps a library diagnostic from hanging the
# hub that raised it. A P2Pevent with nowhere to write became a modal MessageBox
# on whichever thread raised it - the hub's own PUMP for anything reached through
# P2PeerCon::OnClose - and CloseHub() then waits on that pump without a bound. A
# Windows service under the SCM is precisely that shape, so it could deadlock its
# own teardown on any diagnostic at all.
#
# NO PORT, NO HUB, NO RESOURCE_LOCK. It drives P2Pevent::TextOutputPolicy()
# directly, because the two inputs that close the hole cannot be produced from
# inside a test process: it cannot move itself into session 0, and it has no
# business creating an invisible window station to run on.
#
# Registered on BOTH platforms deliberately, although the defect is Windows-only.
# The policy function is compiled everywhere and the table is expressed in its
# inputs rather than in a platform, so a port that changed the rule gets caught
# rather than excused.
#   STATUS: PASSES        (measured 2026-08-17, Windows Debug + Release)
add_executable(p2p_servicedialog p2p_servicedialog.cpp)
_mscs_test_common(p2p_servicedialog)
target_link_libraries(p2p_servicedialog PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_servicedialog COMMAND p2p_servicedialog)
set_tests_properties(p2p_servicedialog PROPERTIES
    TIMEOUT 60 LABELS security)

# p2p_pumpbound: does the queue-full diagnostic name the bound it just enforced?
# ProductionPlan.md Stage 0 step 2. s_cP2PmsgMAX was 50000 and all seven sites
# that tested the depth printed "pump is full, 10000 entries" - the literal had
# outlived the constant, so the one number an operator gets when a hub starts
# refusing work was five times too small.
#
# NO PORT, NO SOCKET, NO RESOURCE_LOCK - it creates the hub on its own thread and
# never pumps, so the queue fills deterministically instead of by out-running a
# consumer. It is memory-hungry rather than slow (the bound is 50000 live
# messages, each a P2PeerMsg32), which is what the timeout is sized for.
#
# NOT labelled `security`: this is availability and operability, not a gate. It
# would have been silent about every attack in this directory.
#
# The test HARDCODES NO FIGURE. It compares the rendered number against the
# capacity the run measured, so lowering s_cP2PmsgMAX and rebuilding is the
# falsification - the test passes reporting the new number, and fails the day a
# literal drifts from the constant again.
#   STATUS: PASSES        (measured 2026-08-18, Windows Debug)
add_executable(p2p_pumpbound p2p_pumpbound.cpp)
_mscs_test_common(p2p_pumpbound)
target_link_libraries(p2p_pumpbound PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_pumpbound COMMAND p2p_pumpbound)
set_tests_properties(p2p_pumpbound PROPERTIES TIMEOUT 300)

# p2p_hubwake: PauseHub() must not be a one-way door.
#
# P2PeerHub::WakeupHub() ran `ASSERT(0); // Requires implementation` in its
# hub-context branch, so every caller that mattered - p2peerhub_wakeup_hub() on
# the flat C surface, P2PeerService::OnContinue (SERVICE_CONTROL_CONTINUE) and a
# raw P2PsigHub_WAKEUP - reached it by the same route and got an abort in Debug
# or a silent return in Release. A paused hub could never be resumed.
#
# Nothing exercised it. The single reference in the tree (TargetcoreSuite.cpp,
# the bogus-handle sweep) is rejected by the handle check before it reaches the
# hub, which is why CI stayed green over an assert on a public entry point.
#
# The probe pauses a BUSY connection, which is the only case a wakeup can help:
# PauseHub latches ConState_CloseOnIdle and drops whatever is already idle, so
# the client posts a 2000 x 2KB burst first and main signals pause + wake while
# that queue is still draining. Three assertions - the burst arrives intact, the
# connection is still there with the latch cleared, and a message posted AFTER
# the wake lands.
#
# FALSIFIED by reverting WakeupHub to its assert and rebuilding: five Release
# runs, five failures - assertion 1 in four of them ("only 1999 of 2000 burst
# messages arrived", i.e. the unwaked latch drops the connection while the tail
# of the burst is still in flight and loses a message), assertion 3 in the
# fifth. Assertion 2 is not the discriminator and its conID check does not make
# it one, because Restart() reuses the P2PeerCon object; it is there to check
# the latch directly in the passing case.
#
# NOT labelled `security`: this is operability. It gates the pause/continue
# contract, not a boundary.
#   STATUS: PASSES        (measured 2026-08-18, Windows Debug + Release)
#           Linux NOT YET MEASURED - the harness is portable by construction
#           (the same shims wsa_mesh uses) but has not been run there.
add_executable(p2p_hubwake p2p_hubwake.cpp)
_mscs_test_common(p2p_hubwake)
target_link_libraries(p2p_hubwake PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_hubwake COMMAND p2p_hubwake)
set_tests_properties(p2p_hubwake PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7833)

# p2p_logindeadline: the second half. Registered on BOTH platforms as of
# ProductionPlan.md Stage 2 step 6, which fixed the Linux drop cascade that had
# kept it behind an if(WIN32).
#
# The instruction left here was "delete the if(WIN32) and re-measure rather than
# assuming, because that cascade passed every Windows run", and that is what was
# done: reproduced on Linux first (RESULT: INCONCLUSIVE - the service stopped
# serving), traced to the IOCP shim delivering completion key 0 for the ops
# closesocket() cancels, fixed by binding the key at submission
# (OVERLAPPED::_p2p_key, Platform/p2piocp.h), and falsified by reverting that one
# line and watching this test go red again. Windows is unaffected by the fix -
# p2piocp.* is compiled only off Windows - and was re-run to confirm it.
#
# Its OWN TARGET off the same source, rather than a second add_test() pointed at
# p2p_acceptcap. That was how it was first written, and it broke two repository
# invariants at once: check_repo_invariants.py requires an add_executable() for
# every `security`-labelled test, and it reads a target's STATUS banner as the
# text since the previous add_executable() - so a test with no target of its own
# has no banner, and its STATUS is absorbed by whichever target comes next
# (p2p_replayguard, which then declared two). The rule those checks enforce is
# the convention this directory already keeps: one test, one executable, verdict
# = exit code. An extra compile of one translation unit is cheaper than an
# exception to it.
#   STATUS: PASSES        (measured 2026-08-18, Windows Debug + Linux)
add_executable(p2p_logindeadline p2p_acceptcap.cpp)
_mscs_test_common(p2p_logindeadline)
target_link_libraries(p2p_logindeadline PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_logindeadline COMMAND p2p_logindeadline 7827 --deadline-only)
set_tests_properties(p2p_logindeadline PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7827 LABELS security)

# p2p_srcbound: the third half, and the one that makes the accept cap mean what
# an operator reads it to mean. ProductionPlan.md Stage 4 step 11.
#
# p2p_acceptcap's own banner used to carry the disclaimer this closes: the cap
# "is per SERVICE connection, not per host and not per source address: one peer
# opening 2 connections and two peers opening one each are the same thing to
# it", because bounding by origin "needs an accounting key this layer does not
# have - the address is not known until the login that has not happened."
#
# Half right. The P2P ADDRESS is unknown until a login the peer holding slots is
# in no hurry to perform - but the SOURCE IP is known at accept, from the kernel,
# about a peer that has said nothing at all. That is the key
# (P2PeerConWsa::AcceptSourceKey), and this is its exit criterion.
#
# FOUR observations, and the LAST is the test. Two connections from 127.0.0.2
# admitted; a third from 127.0.0.2 refused; one from 127.0.0.3 still served.
# Without that last one, a bound that refused the third connection from anywhere
# would pass - which is the service cap p2p_acceptcap already measures, wearing a
# different name. The service cap is deliberately set to 16 rather than off, so
# the refusal happens with fourteen slots free and cannot be read as fullness.
#
# TWO LOOPBACK ADDRESSES, no second machine and no privileges: 127.0.0.0/8 is
# loopback in its entirety on both platforms, and bind() to 127.0.0.2 plus the
# server's getpeername() reporting it back was measured on Windows and Linux
# before this test was written to depend on it. A host that refuses the bind
# reports SETUP (exit 2), not FAIL - that is a fact about the host.
#
# Its OWN TARGET off the same source, for the reason spelled out above
# p2p_logindeadline: check_repo_invariants.py wants an add_executable() per
# security-labelled test and reads this STATUS banner as the text since the
# previous one.
#   STATUS: PASSES        (measured 2026-08-19, Windows Debug + Linux)
add_executable(p2p_srcbound p2p_acceptcap.cpp)
_mscs_test_common(p2p_srcbound)
target_link_libraries(p2p_srcbound PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_srcbound COMMAND p2p_srcbound 7828 --source-only)
set_tests_properties(p2p_srcbound PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7828 LABELS security)

# p2p_pipecap: the same question p2p_acceptcap asks of P2PeerConWsa, asked of
# P2PeerConPipe - and until 2026-09-19 the answer was different. The decision
# helper AcceptAtCapacity() is on the BASE class (P2PeerCon.h:255) and the only
# call to it in the tree was P2PeerConWsa.cpp:1422; pipe, serial and DMX never
# asked. Nothing looked absent at the base, which is why it went unnoticed:
# P2PeerCon.h:237-238 deliberately supplies the decision and leaves the refusal
# to the transport, "because only the transport knows how to discard a
# half-accepted endpoint", and three of the four transports never wrote their
# half. OpenCodeWork.md item 2.
#
# What the pipe had instead was an accident on one platform and nothing on the
# other. CreateNamedPipe takes a literal nMaxInstances of 2
# (P2PeerConPipe.cpp:491), so Windows capped at two clients however
# SetMaxAccepted was set and the third failed inside the kernel; the Linux shim
# ignores that argument and listens with a backlog of 8 (p2psock.h:404).
#
# THE CAP IS 1 AND NOT 2, which is the one design decision in this test worth
# reading before changing. A cap of 2 needs three concurrent clients, and the
# third cannot be served on Windows for the accidental reason above - so the
# test would pass against a library that does nothing. At 1 the refusal lands
# while the pipe still has an instance free and only the library can be
# responsible for it. Same argument as p2p_srcbound's service cap of 16.
#
# PHASE 3 IS THE LOAD-BEARING ONE. A refusal that killed the listener reads
# exactly like a refusal that worked, for as long as nobody knocks again, so
# the first client is closed and a third must get in. It is not hypothetical:
# the first draft of this refusal used DisconnectNamedPipe on both platforms,
# which on Linux is a no-op returning TRUE and would have left m_hFile holding
# a connected socket for Accept() to accept() on.
#
# TWO ctest entries out of one source, as p2p_acceptcap does. --uncapped is the
# CONTROL: with SetMaxAccepted(0) both raw clients must be served, which
# attributes the capped run's drop to the cap rather than to something about
# raw CreateFile clients on a pipe. Run it first on any red.
#
# RESOURCE_LOCK on the NAME, not a port. This transport has no port, and two
# tests sharing the probe pipe name would collide exactly as two sharing a port
# do - more sharply, because CreateNamedPipe here passes
# FILE_FLAG_FIRST_PIPE_INSTANCE and the second service THROWS.
# GATED ON WINDOWS ONLY, AND NOT TO MAKE CI GREEN - measured 2026-09-21. On
# Linux this run FAILS phase 3: the first raw client leaves and a third cannot
# even OPEN the pipe ("third=OPEN REFUSED"), with the library reporting
# "IOCP already created / Incomplete reset or sequence bug" from CreateIOCP
# during phase 2. Phases 1 and 2 pass there - the cap DOES bind on Linux - so
# what is unproven on that platform is specifically the listener's recovery
# after a client departs, which is the Linux named-pipe emulation
# (Msgcore/Platform/p2pfile.h maps \\.\pipe\ onto AF_UNIX) rather than the
# accept bound this row is about.
#
# The EXECUTABLES are still built on both platforms, so the code cannot rot
# and the failure can be reproduced by hand on Linux at any time. It is only
# the ctest registration that is Windows-only, and OpenCodeWork.md carries it
# as an open row with the evidence. seal_interop above is scoped the same way
# for a comparable reason.
#   STATUS: PASSES        (measured 2026-09-21, Windows Debug)
add_executable(p2p_pipecap p2p_pipecap.cpp)
_mscs_test_common(p2p_pipecap)
target_link_libraries(p2p_pipecap PRIVATE targetcore msgcore p2pplatform)
if(WIN32)
    add_test(NAME p2p_pipecap COMMAND p2p_pipecap)
    set_tests_properties(p2p_pipecap PROPERTIES
        TIMEOUT 120 RESOURCE_LOCK pipe_P2PcapProbe LABELS security)
endif()

# p2p_pipecap_control: the uncapped control, its own ctest entry for
# p2p_srcbound's reason - one mode, one verdict, one exit code. A phase spliced
# into the run above would print a second RESULT line underneath the first.
# WINDOWS ONLY TOO, and that is deliberate rather than consequential: this
# control exists to make the capped run's refusal attributable, so running it
# on a platform where the capped run is not registered would assert nothing
# about anything. It PASSES on Linux today; that is recorded and is not a
# reason to keep it.
#   STATUS: PASSES        (measured 2026-09-21, Windows Debug)
add_executable(p2p_pipecap_control p2p_pipecap.cpp)
_mscs_test_common(p2p_pipecap_control)
target_link_libraries(p2p_pipecap_control PRIVATE targetcore msgcore p2pplatform)
if(WIN32)
    add_test(NAME p2p_pipecap_control COMMAND p2p_pipecap_control --uncapped)
    set_tests_properties(p2p_pipecap_control PROPERTIES
        TIMEOUT 120 RESOURCE_LOCK pipe_P2PcapProbe LABELS security)
endif()

# p2p_dmxcap: the same question again, asked of P2PeerConDmx - the in-process
# transport, and the last of the four that OpenCodeWork.md item 2 named. The
# decision helper AcceptAtCapacity() is on the base class (P2PeerCon.h:255);
# until this test the only callers were P2PeerConWsa.cpp:1422 and, since
# 2026-09-20, P2PeerConPipe. DMX never asked.
#
# THE REFUSAL IS A DIFFERENT SHAPE HERE and the test is built around that. A
# DMX link is two P2PeerConDmx objects in one address space pointing at each
# other, and the CLIENT latches both back-pointers itself inside Connect()
# before the service is asked anything (P2PeerConDmx.cpp:788-813). So the
# service cannot decline a connection it has not adopted, the way Wsa does; it
# has to detach one that is already attached, which is OnClose()'s sequence.
#
# NO RAW CLIENT, unlike p2p_acceptcap and p2p_pipecap. Those open the transport
# by hand because the adversary does not run this library and will not complete
# a handshake. In-process there is no such adversary - a hand-rolled DMX client
# would just be a copy of Connect() - so the clients here are real hubs and the
# bound being measured is narrower: resource exhaustion by components of this
# process, not by a remote peer.
#
# THE CAP IS 1, for p2p_pipecap's reason carried over: a smaller cap puts the
# refusal where only the library can be responsible for it.
#
# ITS THIRD PHASE IS NOT p2p_pipecap's THIRD PHASE, and the difference is a
# measurement rather than a shortcut. There the first client is closed and a
# later one must be served, which proves the accepted SLOT comes back. Here
# the BOUND is raised instead, which proves the SERVICE is still listening
# after it refused someone - the failure this refusal could plausibly cause,
# since a refusal that forgets to drop the consumed accept leaves the
# unconditional re-arm in P2PeerTarget::On_ConAccept throwing. The slot
# question is asked by p2p_dmxcap_slot below, which is BUILT BUT NOT GATED
# because the answer is still no: on this transport the slot does not come
# back, and that is OpenCodeWork.md item 7 - open, diagnosed, not closed.
#
# NO RESOURCE_LOCK, and that is the transport rather than an omission: every
# link is a pointer handoff inside the test process. There is no port and no
# pipe name for a parallel ctest job to collide with, so these two entries can
# run alongside anything - including each other, which is why the control is
# cheap here in a way it was not on the pipe.
#   STATUS: PASSES        (measured 2026-09-20, Windows Debug)
add_executable(p2p_dmxcap p2p_dmxcap.cpp)
_mscs_test_common(p2p_dmxcap)
target_link_libraries(p2p_dmxcap PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_dmxcap COMMAND p2p_dmxcap)
set_tests_properties(p2p_dmxcap PROPERTIES
    TIMEOUT 120 LABELS security)

# Its OWN TARGET off the same source, and on this transport the control is
# load-bearing rather than tidy. Nothing else in the tree shows that one DMX
# service can hold two accepted connections at once; if it cannot, the capped
# run's phase 2 passes against a library that does nothing at all. This entry
# asserts the two clients are BOTH served when SetMaxAccepted(0) unbounds them,
# which is what makes the capped run's refusal attributable to the cap. On the
# pipe the equivalent control is what separated two defects that had looked
# like one.
#   STATUS: PASSES        (measured 2026-09-20, Windows Debug)
add_executable(p2p_dmxcap_control p2p_dmxcap.cpp)
_mscs_test_common(p2p_dmxcap_control)
target_link_libraries(p2p_dmxcap_control PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_dmxcap_control COMMAND p2p_dmxcap_control --uncapped)
set_tests_properties(p2p_dmxcap_control PROPERTIES
    TIMEOUT 120 LABELS security)

# p2p_dmxcap_slot: does a DEPARTING client give its accept slot back? This is
# the question the two entries above cannot ask, and it is a DIFFERENT DEFECT
# from the bound they measure - OpenCodeWork.md item 7, found by building
# them.
#
# A THIRD TARGET RATHER THAN A FOURTH PHASE, deliberately. p2p_dmxcap answers
# "does the bound bind"; this answers "is the bound a concurrency limit or a
# lifetime total". A binary that can go red for two unrelated reasons tells
# whoever reads the CI line neither of them, and these two regress
# independently: the first is about OnAccept, the second about teardown.
#
# It asks two things in order because they fail differently. First the
# accounting: GetAcceptedCount() must return to 0 once the client's hub is
# closed, joined AND destroyed - the count is decremented by ~P2PeerCon and
# nothing else (P2PeerCon.cpp:146-151, the only release path, deliberately),
# so a count that does not move means the accepted connection is still alive.
# Then the consequence: a later client must actually be served in the freed
# slot, which can fail even when the accounting is right, if the service
# stopped listening.
#
# BUILT BUT NOT GATED, and NOT because it is unfinished - because it is RED,
# and the defect it is red on is not one that can be closed from here.
# teardown_stress below is built the same way for the same kind of reason.
# There is deliberately no add_test and deliberately no WILL_FAIL: a red entry
# would break CI and a WILL_FAIL one would make CI green on a live defect,
# which this file refuses everywhere else. Run it by hand:
#     build/windows-msvc/MscsUnitTests/Debug/p2p_dmxcap_slot.exe --slotreturn
#
# WHAT IT REPORTS TODAY (measured 2026-09-21, Windows Debug): the client hub
# is closed, joined and destroyed, and the service's GetAcceptedCount() is
# still 1 ten seconds later. So SetMaxAccepted() on this transport is a
# LIFETIME TOTAL, not the concurrency limit P2PeerCon.h:242 documents.
#
# A FIX WAS BUILT AND REVERTED, and the reason is worth the paragraph. Three
# causes were found and fixed, each only visible once the one before it was:
# the wake in P2PeerConDmx::Drop() required the peer to have a QUEUED recv,
# which an idle in-process link never has; P2PeerConDmx::OnClose() never
# destroyed an accepted connection and COULD NOT, because three transports
# declared a non-virtual Destroy() that hid P2PeerConPlc::Destroy() and that
# nothing defined; and the wake still did not wake, because PostOVERLAPPED()
# calls prepareOVERLAPPED(), which assigns hr = S_OK - so all four sites in
# the tree that set hr = ERROR_OPERATION_ABORTED before posting were posting a
# SUCCESS. With all three fixed this entry passes.
#
# It was reverted because it destabilised the suite: p2pweb wires its hub
# chain with P2PeerConDmx (WebChainBuilder.cpp:477), and p2pweb_w6 began
# SEGFAULTing at teardown after its last assertion, in roughly half of all
# runs on 2026-09-21 - confirmed against a reverted library, not assumed. Cause:
# is that the bQueued guard was doing TWO jobs: P2PeerCon.cpp:1287-1300 states
# that a queued member OVERLAPPED also means one reference is held and the
# connection cannot reach zero. Waking an IDLE peer therefore posts to a
# connection with no references at all. Holding a reference across the post
# did not settle it either. Closing this properly is reference-safe peer
# notification in a refcounted teardown - a design change to DMX, not a patch.
# OpenCodeWork.md item 7 carries the full measurement.
add_executable(p2p_dmxcap_slot p2p_dmxcap.cpp)
_mscs_test_common(p2p_dmxcap_slot)
target_link_libraries(p2p_dmxcap_slot PRIVATE targetcore msgcore p2pplatform)

# p2p_dmxdead: does a DMX send to a peer that has GONE report that it failed,
# or that it worked? OpenCodeWork.md item 7's SECOND exit criterion, and a
# different defect from the row's main one: item 7 is about a connection that
# is never told its peer left, this is about one that HAS been told and is
# then asked to send.
#
# It reported that it worked. P2PeerioDmx::SendP2PeerMsg refuses when
# GetUDState() is 0 - which on this transport is literally m_pConThat - by
# writing hr = ERROR_OPERATION_ABORTED and posting. prepareOVERLAPPED()
# assigns hr = S_OK and PostOVERLAPPED() calls it, so the abort was erased by
# the post it was written for and the completion arrived a SUCCESS. The send
# branch treats a success as delivered and DELETES THE MESSAGE
# (P2PeerCon.cpp:691-697). So a message handed to a peer that no longer
# exists was destroyed and the sender told it went.
#
# THE CONTROL IS LOAD-BEARING. The fix makes a dead-peer send drop the
# connection, so something has to show that a send does not drop a connection
# by being a send. --alive asserts the same message on the same call ARRIVES,
# positively, and that nothing closes.
#
# ONLY THE SEND HALF IS FIXED AND GATED. The recv half of the identical
# defect (P2PeerioDmx.cpp:177-181) is measured and deliberately untouched: with
# it fixed, p2pweb_w6 SEGFAULTs at teardown - p2pweb wires its hub chain with
# P2PeerConDmx, and a recv is re-armed constantly during shutdown, so turning a
# silent re-arm into a connection drop reorders how every in-process chain
# comes down. Measured 2026-09-21, one failure in the first run of the pair
# fixed together, and five clean runs with the send half alone. That half goes
# with item 7's teardown work.
#
# NO RESOURCE_LOCK: the link is a pointer handoff inside the test process.
#   STATUS: PASSES        (measured 2026-09-21, Windows Debug)
add_executable(p2p_dmxdead p2p_dmxdead.cpp)
_mscs_test_common(p2p_dmxdead)
target_link_libraries(p2p_dmxdead PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_dmxdead COMMAND p2p_dmxdead)
set_tests_properties(p2p_dmxdead PROPERTIES
    TIMEOUT 120 LABELS security)

#   STATUS: PASSES        (measured 2026-09-21, Windows Debug)
add_executable(p2p_dmxdead_control p2p_dmxdead.cpp)
_mscs_test_common(p2p_dmxdead_control)
target_link_libraries(p2p_dmxdead_control PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_dmxdead_control COMMAND p2p_dmxdead_control --alive)
set_tests_properties(p2p_dmxdead_control PROPERTIES
    TIMEOUT 120 LABELS security)


# p2p_listenscope: can a SERVICE be told not to be reachable from off this
# machine? Targetcore P2PeerConWsa::SetListenScope, added 2026-08-27.
#
# P2PeerConWsa::Listen() bound INADDR_ANY as a LITERAL from the import, with no
# setting anywhere on the class to say otherwise, so every service this library
# has ever stood up has been reachable from every interface its host routes. A
# deployment that wanted less could only get it from outside the process, in a
# firewall, where nothing in the library could read it back - THREAT_MODEL.md
# asset S9 twice over: a protection that is off, and one that cannot be seen to
# be off.
#
# THE CONTROL IS THE TEST, and it runs FIRST. The DEFAULT scope must be
# reachable on this host's own non-loopback address before the loopback scope is
# asked to refuse it. Without that, a host whose firewall drops that address
# reports a bind restriction it does not have, and so does a tree where Listen()
# has simply been broken. A failed control is INCONCLUSIVE (exit 3) rather than
# FAIL: it is a fact about the host, not about the library. A host with no
# non-loopback IPv4 at all reports SETUP (exit 2) rather than comparing loopback
# against loopback and passing on anything.
#
# HOW IT FINDS THAT ADDRESS CHANGED ON 2026-08-28, and the reason is the first
# time this test was ever run on Linux. It resolved gethostname() through
# getaddrinfo(), which is a WINDOWS convention: there a machine's name maps to
# the address it is reachable on. Debian and Ubuntu write `127.0.1.1 <hostname>`
# into /etc/hosts, so on a VM sitting on a live 192.168.1.x interface the lookup
# returned LOOPBACK, this found nothing, and the gate reported SETUP and skipped
# itself. It asks the routing table now - a UDP connect() to RFC 5737 TEST-NET-1,
# which sends nothing and needs no privilege, then getsockname() - which is the
# portable way to ask which of my addresses reaches off this machine.
#   STATUS: PASSES        (measured 2026-08-28, Windows Debug + Linux gcc Debug)
add_executable(p2p_listenscope p2p_listenscope.cpp)
_mscs_test_common(p2p_listenscope)
target_link_libraries(p2p_listenscope PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_listenscope COMMAND p2p_listenscope 7847 --scope-only)
set_tests_properties(p2p_listenscope PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7847 LABELS security)

# p2p_acceptfilter: WHO may connect, as against WHERE the service listens.
# Targetcore P2PeerConWsa::AllowAcceptFrom, added beside the scope above.
#
# ITS OWN TARGET off the same source, for p2p_srcbound's reason: one mode, one
# verdict, one exit code, and check_repo_invariants.py reads the STATUS banner
# as the text since the previous add_executable().
#
# WHY A SOURCE TEST EXISTS AT ALL when the bind above is kernel-enforced and
# this is not: A BIND CANNOT EXPRESS "THE LAN". Binding to a LAN interface's
# address restricts which INTERFACE accepts, not which SOURCE reaches it - a
# packet forwarded in from the internet by a NAT or a port-forward arrives on
# that same interface and is accepted. The two settings are complementary and
# neither replaces the other.
#
# FOUR observations against AllowAcceptFrom("127.0.0.2") with BOTH accept caps
# off, so nothing but the allow-list can refuse anything. 127.0.0.2 is SERVED -
# the positive control, and without it a filter that refused everybody would
# pass, which is p2p_srcbound's lesson wearing a different name. 127.0.0.3 is
# CLOSED. An unnameable source (key 0) is REFUSED by a configured filter and
# ADMITTED by an unconfigured one - the fail-CLOSED rule and its converse, and
# the deliberate opposite of SourceAtCapacity() one line away in AcceptSpawn().
# And a malformed prefix is rejected AND adds nothing: inet_addr() reads "10.1"
# as 10.0.0.1 and "0x0a000001" as an address, which is a convenience at a prompt
# and a hazard in a policy file.
#
# It asks IsAcceptSourceAllowed() DIRECTLY as well as through a socket, because
# THREAT_MODEL.md §2 records what it cost to learn that a gate must measure the
# DECISION and not a consequence of it - the F-S6-1 gate passed against the tree
# that had the defect.
#
# THE PARSER THIS EXERCISES DID NOT COMPILE ON LINUX until 2026-08-28. It was
# written against CStringA::Find/Mid/Left/Trim/operator[] and ../Msgcore/Platform's
# CStringA carries none of them, so P2PeerConWsa.cpp - the whole transport -
# failed to build there from the day this gate landed. Nothing built that file
# on Linux in between. It now parses from a plain char buffer and needs no
# string class, which is also why the rejections this test names one by one are
# the same on both platforms rather than only defined on one.
#   STATUS: PASSES        (measured 2026-08-28, Windows Debug + Linux gcc Debug)
add_executable(p2p_acceptfilter p2p_listenscope.cpp)
_mscs_test_common(p2p_acceptfilter)
target_link_libraries(p2p_acceptfilter PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_acceptfilter COMMAND p2p_acceptfilter 7848 --filter-only)
set_tests_properties(p2p_acceptfilter PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7848 LABELS security)

# p2p_resolve: can a client dial a peer by NAME? Nothing in this suite asked
# until 2026-08-28, and the answer was no.
#
# P2PeerConWsa::Connect() tested `InetPton(...) == INADDR_NONE` to decide
# whether to fall back to gethostbyname(). That test was written for
# inet_addr(), which signals failure with INADDR_NONE; InetPton() answers 0 and
# WRITES NOTHING, so the address stayed 0.0.0.0 and the branch could only fire
# for the literal "255.255.255.255". gethostbyname() was unreachable, every host
# NAME resolved to 0.0.0.0, and the failure surfaced from ConnectEx as
# WSAEADDRNOTAVAIL instead of the "Unable to resolve server" the dead branch
# meant to report. The documented SELF-CONNECTION path - empty address, served
# by feeding gethostname()'s answer back in - went the same way.
#
# THE SUITE WAS GREEN THROUGHOUT because every other test in it dials the
# literal "127.0.0.1", which parses. This file is the one that passes a name,
# and that is the whole reason it exists: the defect was not subtle, it was
# UNASKED.
#
# REAL HUBS, not raw sockets - the subject is the library's own Connect(), so
# the test has to go through it. Three dials against a fresh server each time:
# the literal (control, or a broken harness reads as a broken resolver), the
# name "localhost" (the measurement), and a name RFC 6761 reserves to be
# unresolvable (negative control). A network that hijacks NXDOMAIN makes the
# third INCONCLUSIVE rather than FAILED - that is a fact about the network.
#
# NOT LABELLED `security`. It is a correctness gate: no protection depends on a
# name resolving, and a client that cannot reach its peer is an availability
# problem rather than an admission one. It therefore declares no STATUS banner,
# which check_repo_invariants.py requires only of security-labelled tests.
add_executable(p2p_resolve p2p_resolve.cpp)
_mscs_test_common(p2p_resolve)
target_link_libraries(p2p_resolve PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_resolve COMMAND p2p_resolve 7849)
set_tests_properties(p2p_resolve PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7849)

# p2p_ipv6: can this transport speak IPv6 at all? Targetcore
# P2PeerConWsa::SetFamily, added 2026-08-28.
#
# P2PeerConWsa opened AF_INET at all three socket sites - Listen(), Accept() and
# Connect() - and carried sockaddr_in for the bind and the dial, from the import
# until that date. A v6 peer could not reach a service and a client could not
# dial one. What made that a DEFAULT rather than a limitation is that nothing
# said so and nothing could be told otherwise: Readme.md recorded "TCP is IPv4
# only" and there was no setting to change it.
#
# THE HOST CAN BE THE REASON, so it is asked FIRST. A machine that will not bind
# ::1 has no IPv6 stack to measure the library against and reports SETUP (exit
# 2) rather than FAIL - a v6-disabled Windows image is a supported deployment,
# and a gate that cannot tell "the library will not do this" from "this host
# will not do this" is not a gate. The IPv4 control runs before the measurement
# for the same reason p2p_listenscope's does.
#
# THE HALF THAT WOULD PASS SILENTLY: a v6-only service must REFUSE a v4 client.
# IPV6_V6ONLY is set explicitly in both directions because the platforms
# disagree - Windows defaults it ON, most Linux distributions default it OFF -
# so a socket that did not say would be v6-only on one build and dual-stack on
# the other from identical source. A "v6-only" service that quietly admits v4 is
# THREAT_MODEL.md asset S9: a protection whose real state cannot be read off the
# code. THAT ASSERTION IS THE REASON THE LINUX RUN IS NOT OPTIONAL for this
# gate: on Windows it passes whether or not the option is set, and on Linux it
# passes only because it is. Measured on both.
#   STATUS: PASSES        (measured 2026-08-28, Windows Debug + Linux gcc Debug)
add_executable(p2p_ipv6 p2p_ipv6.cpp)
_mscs_test_common(p2p_ipv6)
target_link_libraries(p2p_ipv6 PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_ipv6 COMMAND p2p_ipv6 7850 --v6-only)
set_tests_properties(p2p_ipv6 PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7850 LABELS security)

# p2p_ipv6dual: ONE SOCKET, BOTH FAMILIES.
#
# ITS OWN TARGET off the same source, for p2p_acceptfilter's reason: one mode,
# one verdict, one exit code, and check_repo_invariants.py reads the STATUS
# banner as the text since the previous add_executable().
#
# BOTH HALVES ARE REQUIRED and that is the whole point. Serving only v6 is
# IPV6_V6ONLY left on; serving only v4 is not a dual-stack socket at all. Scope
# is ANY because DUAL cannot express a loopback scope - ::1 is not the v4-mapped
# form of 127.0.0.1, so one socket cannot bind both loopbacks and Listen()
# refuses the pair rather than silently narrowing one of them.
#   STATUS: PASSES        (measured 2026-08-28, Windows Debug + Linux gcc Debug)
add_executable(p2p_ipv6dual p2p_ipv6.cpp)
_mscs_test_common(p2p_ipv6dual)
target_link_libraries(p2p_ipv6dual PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_ipv6dual COMMAND p2p_ipv6dual 7851 --dual)
set_tests_properties(p2p_ipv6dual PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7851 LABELS security)

# p2p_ipv6filter: does an allow-list mean the SAME THING on a v4 socket and a
# dual one? The companion to p2p_acceptfilter, which measures the v4 half.
#
# WHERE THE TWO ADDRESS SPACES TOUCH, and the reason this phase exists: a
# dual-stack socket reports a v4 peer as ::ffff:a.b.c.d. Left alone, an
# operator's "127.0.0.0/8" would admit that peer on a v4 service and refuse it
# on a dual one, for no reason the operator can see. So a DUAL service allowing
# ONLY "127.0.0.0/8" must SERVE a v4 client - the normalisation - and CLOSE a v6
# client on ::1, because a list of rules in one family refuses every source of
# the other and that trap is worth pinning down rather than discovering.
#
# It asks IsAcceptSourceAllowed() DIRECTLY as well as through a socket, because
# THREAT_MODEL.md §2 records what it cost to learn that a gate must measure the
# DECISION and not a consequence of it. The parser half is p2p_acceptfilter's
# rule in the second family: "::1/129", a zone index "fe80::1%eth0" that no rule
# may carry, and "gg::1" are rejected AND add nothing.
#   STATUS: PASSES        (measured 2026-08-28, Windows Debug + Linux gcc Debug)
add_executable(p2p_ipv6filter p2p_ipv6.cpp)
_mscs_test_common(p2p_ipv6filter)
target_link_libraries(p2p_ipv6filter PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_ipv6filter COMMAND p2p_ipv6filter 7852 --v6filter)
set_tests_properties(p2p_ipv6filter PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7852 LABELS security)

# p2p_hubsnap: can a hub be WATCHED by something that was not built into it?
# ProductionPlan.md Stage 4 step 13.
#
# P2PeerHub::Serialise() is the snapshot the library already pushes everywhere -
# MSG_P2PexpHub is built from it, every P2Pevent carrying hub state carries it -
# and until step 13 it reported six fields of IDENTITY (name, address, domain,
# two version forms) and not one of STATE. The two numbers an operator actually
# wants both already existed and were both exported: GetP2PmsgCount() since the
# import and GetAcceptedCount() since Stage 4 step 10. Neither was in the
# snapshot, so neither could be reached from the far end of a message.
#
# THE RESTRICTION ON THE MONITOR IS THE TEST. The reader in this binary calls
# nothing but the public Serialise() and applies a threshold to named fields. A
# monitor permitted to call GetAcceptedCount() directly would prove the counter
# works - which was already known - rather than that the snapshot carries it.
#
# WHY IT MAKES THE QUEUE DEPTH NON-ZERO BY HAND. A field hard-wired to 0 passes
# any test that only reads it, and that is not hypothetical: PumpsMax has been
# in this snapshot since the import, filled with a literal 0 on every hub that
# ever ran, and nothing noticed. So phase 3 creates a SECOND pump on a worker
# thread that never pumps it, posts four messages to it, and requires the hub's
# depth to see them - which is also the claim that the field is HUB-scoped and
# not the per-pump GetP2PmsgCount() under a new name, since that call cannot see
# another thread's pump at all. Then the worker closes its pump and the depth
# must return to 0.
#
# SECURITY LABEL, on an observability test, for two reasons. Accepted is the
# operator-visible half of the accept bounds p2p_acceptcap and p2p_srcbound
# enforce - a bound nobody can watch approaching is a bound discovered at the
# refusal - and the phase-3 pump is created, posted to and destroyed across
# threads, which is worth having under the sanitiser sweep.
#
# ITS OWN SOURCE and its own port (7834), no --flag dispatch: unlike
# p2p_acceptcap this measures one thing and has one verdict.
#   STATUS: PASSES        (measured 2026-08-19, Windows Debug + Linux)
add_executable(p2p_hubsnap p2p_hubsnap.cpp)
_mscs_test_common(p2p_hubsnap)
target_link_libraries(p2p_hubsnap PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_hubsnap COMMAND p2p_hubsnap 7834)
set_tests_properties(p2p_hubsnap PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7834 LABELS security)

# p2p_conreap: is a connection whose peer LEAVES actually let go of?
# ProductionPlan.md F-S4-1.
#
# A stream socket announces an orderly close by completing an outstanding read
# with ZERO BYTES - and at P2PeerCon's recv branch that is byte-for-byte what
# an ARMING post looks like. PostOVERLAPPED() and RearmRecv() do not issue a
# read; they PostQueuedCompletionStatus(.., 0, ..) so the completion re-enters
# On_QueuedCompletionStatus and RecvP2PeerMsg() issues the real one. Both
# arrive as success carrying zero, and on Windows nothing else told them apart.
# So the FIN was taken for an arming post: no message parsed, no further read
# posted, return - and the connection was never dropped, never destroyed, and
# the destructor that decrements the accepted tally never ran.
#
# WHY IT IS A SECURITY TEST AND NOT A LEAK TEST. With connections EVER ACCEPTED
# standing in for connections currently HELD, SetMaxAccepted(1024) retires a
# service permanently after 1024 connect-and-leave cycles from anywhere, and
# the per-source share retires one address after its share - which makes the
# admission control p2p_acceptcap and p2p_srcbound enforce a slower version of
# the attack it exists to refuse.
#
# FOUR PHASES, AND EACH EXISTS BECAUSE THE OTHER THREE WOULD PASS WITHOUT IT.
# At rest is 0; three raw peers are HELD at exactly 3 (the positive control -
# a hub that refused all three would also report 0 after they closed and would
# pass a test that only watched the fall); they close and it must return to 0
# (the decision); and then a fourth peer that STAYS must still be held 1.5s
# later. That last one is not symmetry. The cheapest way to pass the first
# three is to drop every connection at accept, and that is not hypothetical -
# it is what the obvious fix did when it was tried, because the arming post is
# itself a zero-byte success. The submission mark is what separates them.
#
# NO LOGIN DEADLINE, SET EXPLICITLY. SetLoginDeadline() is a reaping path that
# works on both platforms, so a deadline armed here would reap these peers for
# a reason that is not the close and the test would pass against the defect.
# p2p_srcbound uses that path deliberately and says so; this one must not.
#
# ITS OWN PORT (7842) and its own source: one thing measured, one verdict.
#
# F-S4-2. This harness leaked the thread handle SpawnHub() hands back - 80
# bytes in 3 allocations, every run - and nothing could have caught it: a
# leaked handle in a process about to exit costs nothing a test can observe.
# It took the FIRST sanitised run this test had ever had, on 2026-08-20. It is
# in the security label and always was; the tree that last reported that
# label's Linux figure simply predated it. A label total quoted from a tree
# missing two of its members is a figure about a different label.
#   STATUS: PASSES        (measured 2026-08-20, Windows Debug + Release, Linux,
#                          and Linux ASan+UBSan+LSan with detect_leaks=1)
add_executable(p2p_conreap p2p_conreap.cpp)
_mscs_test_common(p2p_conreap)
target_link_libraries(p2p_conreap PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_conreap COMMAND p2p_conreap 7842)
set_tests_properties(p2p_conreap PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7842 LABELS security)

# p2p_imagegen: the message image's LAYOUT GENERATION, on the wire and in the
# store. VERSIONING.md 6, the second of the two open 1.0 gates.
#
# The image header has no version field and no room for one - 24 bits of size,
# 2 of addressing mode, 6 of endian sentinel - so the SENTINEL is the version
# field, and this gate is what makes that true rather than merely arguable. It
# checks three propositions that are easy to state and were not checked by
# anything:
#   (1) a current-generation frame still parses          (positive control)
#   (2) EVERY other generation is refused ON THE WIRE, by a diagnostic that
#       names which one arrived
#   (3) a pre-sentinel image still LOADS FROM DISK
# (3) is not decoration. Without it, "refuse legacy everywhere" passes (2) and
# quietly invalidates stored data, which is the opposite of the decision taken.
#
# ONE OF ITS CASES WAS RED ON THE TREE THAT PRECEDED IT AND THE OTHERS WERE
# NOT, which the source says in as many words rather than leaving to be
# discovered. A pre-sentinel frame used to be ACCEPTED end to end, because
# stage 2 tests only the complement and P2PmsgHeap_IsIOMAGE accepts
# VBLockSync_Legacy; that case is the break. The other-generation cases were
# already refused as corruption, and what they assert is the DIAGNOSTIC - a
# refusal that cannot say what arrived cannot be acted on. They SWEEP the code
# space rather than naming a reserved code, because the classifier is a
# fallback and not a registry of reserved generations: four of the six codes
# they drive are ones no registry would ever have listed.
#
# NO PORT, NO HUB, NO RESOURCE_LOCK. It drives P2Peerio::RecvP2PeerMsg through
# the same bQueued seam p2p_fuzzframe documents, so the parser under test is
# the shipping one and nothing is stubbed.
#
# Labelled `security`: everything it exercises is PRE-AUTH. The framing path is
# reachable by anyone who can open a TCP connection.
# ITS FIRST SANITISED RUN FOUND A DEFECT IN THE CODE IT WAS WRITTEN FOR, which
# is the argument for the sanitiser gate rather than a footnote to it. The
# store-side warning this gate exists to require was raised with `->Display()`
# and nothing else, and Display() neither disposes the event nor hands it to
# anybody: LSan reported 21,284 bytes in 27 allocations, every frame rooted in
# P2PmsgMgr::Load. `->Cancel(true)` displays once, notifies and DELETES. The
# two EVWRN sites that already existed end `->Display()->SetLast()`, which does
# not leak because SetLast puts the event in thread-local storage for the next
# one to displace - a different answer to the same question, and the wrong one
# here because nothing needs to retrieve this warning.
#   STATUS: PASSES        (measured 2026-08-20, Windows Debug + Release, Linux,
#                          and Linux ASan+UBSan+LSan with detect_leaks=1)
add_executable(p2p_imagegen p2p_imagegen.cpp)
_mscs_test_common(p2p_imagegen)
target_link_libraries(p2p_imagegen PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_imagegen COMMAND p2p_imagegen)
set_tests_properties(p2p_imagegen PROPERTIES
    TIMEOUT 60 LABELS security)

# p2p_framegate: the UNTRUSTED GATE over an arriving message image.
# ProductionPlan.md Stage 1 step 4, and the test that closes it stays closed.
#
# WHY IT EXISTS WHEN p2p_fuzzframe ALREADY DRIVES THE SAME PARSER. The assert
# budget next to it can only go red in a DEBUG build: ASSERT is compiled out of
# Release, so the tally there is zero whether the code is right or wrong, and
# the harness prints that caveat on every Release run. The defect this file
# pins was precisely a Release-only one - stage 4 adopted an image through a
# constructor whose two block walks sit INSIDE ASSERT(), so Debug walked the
# chain and threw the answer away while Release never walked it. Undo the fix
# and the fuzz gate goes red in Debug and STAYS GREEN IN RELEASE. This one does
# not, because none of its three propositions is spelled with an assertion:
#   (1) positive control, through both entry points
#   (2) what the length-validated adoption path REFUSES, the receive path must
#       also refuse - the one-argument constructor's defect as a property
#   (3) a refused image is byte-identical to what arrived - the block walks
#       used to end by writing the image's own root back into agreement with
#       what they had just counted, which is a validator editing the bytes it
#       was asked to judge
#
# IT SWEEPS RATHER THAN NAMING CASES, and the reason is in the defect: the two
# fields that were actually wrong - a block header's step size and the ROOT'S
# aAlloc LINK, which neither walk looked at - sit at offsets nobody had written
# a case for. A sweep cannot miss a field for want of being told about it. It
# carries a VACUITY GUARD because a sweep needs one: if the gate stopped
# refusing anything, (2) and (3) would both pass perfectly, so the run fails
# unless a floor of the sweep is refused, and it prints the count either way.
# The floor is 40, far under what is measured - 111 of 409 mutants refused on
# Windows - so it catches a gate that has STOPPED and not a serializer change
# that moves the count.
#
# BOTH ITS PROPOSITIONS WERE PROVEN RED BEFORE THEY WERE BELIEVED, separately,
# in a RELEASE build, which is the configuration that could not be gated
# before. Reverting stage 4 to the one-argument constructor: (2) reports "76
# image(s) the length-validated path REFUSED were still parsed into a message".
# Making the root fixups unconditional again: (3) reports "29 refused image(s)
# were MODIFIED by the walk that refused them".
#
# AND LSan STAYS ON FOR IT, which p2p_fuzzframe cannot manage - see the
# detect_leaks=0 exemption further down and the reason recorded with it. A
# throw out of stage 4 leaves ownership of the frame buffer undecidable FROM
# OUTSIDE, so a fuzzer has to leak it rather than risk a double free being read
# as a finding. This harness has the answer the fuzzer lacks: it has already
# asked the adoption path about the same bytes, and a refusal there means the
# create detached the image, so the buffer is still the caller's. It frees on
# that and leaks nothing. Its first Linux sanitiser run reported 217,852 bytes
# in 107 allocations from P2Peerio.cpp:530 - the deliberate-leak line copied
# from p2p_fuzzframe, before the verdict was threaded in - so this is measured
# rather than argued, and a double free would now be reported as one. That
# makes the ownership contract the fix introduced something this test CHECKS
# rather than something it works around.
#
# NO PORT, NO HUB, NO RESOURCE_LOCK: the same bQueued seam p2p_fuzzframe and
# p2p_imagegen document, so the parser under test is the shipping one.
#
# Labelled `security`: all of it is PRE-AUTH.
#   STATUS: PASSES        (measured 2026-08-22, Windows Debug + Release,
#                          Linux Debug + Release, Windows ASan, and Linux
#                          ASan+UBSan+LSan with detect_leaks=1)
add_executable(p2p_framegate p2p_framegate.cpp)
_mscs_test_common(p2p_framegate)
target_link_libraries(p2p_framegate PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_framegate COMMAND p2p_framegate)
set_tests_properties(p2p_framegate PROPERTIES
    TIMEOUT 120 LABELS security)

# p2p_backpressure: is the message budget a SLOPE or a CLIFF?
# ProductionPlan.md Stage 4 step 12.
#
# s_cP2PmsgMAX bounds the live P2Pmsg's in a process and, until step 12, the only
# thing that happened at it was a throw - raised on whichever thread happened to
# post the message that crossed it, which is almost never the thread or the
# connection responsible. Below it there was nothing at all: a peer could send as
# fast as it liked right up to the edge.
#
# Two marks now make the same budget a slope. At or above HIGH a connection stops
# asking its transport for more - expressed by NOT calling RecvP2PeerMsg(), the
# call that issues the next Recv() - so no read is outstanding, the socket buffer
# fills and the TCP window closes. At or below LOW it starts again. The gap is
# hysteresis: with one mark a connection resumes the instant the budget dips a
# message below it and is immediately re-held, which is a spin rather than a brake.
#
# A LOGGED-IN PEER, not a raw socket. An application message from an
# unauthenticated peer is refused by GateAppMsgInbound() before it reaches a pump,
# so a raw flooder would measure the login gate instead. The peer throttled here
# has done nothing wrong - the pressure is the process's, not its fault.
#
# PHASE 3 IS THE ONE THAT MATTERS. Phase 2 shows messages not arriving, which a
# hub that simply dropped them would also show. Phase 3 releases the pressure and
# requires every held message to arrive: throttling that loses messages is
# dropping with a better name.
#
# THE MARKS ARE LOWERED FOR THE RUN via SetP2PmsgBudgetMarks, because a gate that
# needed 37500 live messages would be too slow to be a gate. The product defaults
# (three quarters and one half of the ceiling) are unchanged and always on.
#
# TWO HUBS, one port (7835), and its own source: this needs a real socket between
# two hubs, which no other file here sets up alongside a parked pump.
#   STATUS: PASSES        (measured 2026-08-19, Windows Debug + Linux)
add_executable(p2p_backpressure p2p_backpressure.cpp)
_mscs_test_common(p2p_backpressure)
target_link_libraries(p2p_backpressure PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_backpressure COMMAND p2p_backpressure 7835)
set_tests_properties(p2p_backpressure PROPERTIES
    TIMEOUT 180 RESOURCE_LOCK loopback_7835 LABELS security)

# p2p_replayguard: RefuseSealReplay and RefuseRelayReplay, reached through the
# HUB. AuthSelfTest sections 17 and 18 pin the cache semantics thoroughly at
# p2pauth::AuthPolicy level, including the count bound and the eviction it
# implies. What nothing touched was the wiring: the P2PeerHub setters under
# m_oCSectionHub, and a sealed body opened on a live receive path rather than in
# a loop. That left the newest security code in the tree as the least-tested,
# which is the wrong way round.
#
# The replay is the IDENTICAL BYTES posted twice - what a capture-and-redeliver
# attacker actually has, because it is what went over the wire. Both halves run
# their control with the switch OFF first: until a replay demonstrably gets
# through, a refusal is not evidence of a guard.
#   STATUS: PASSES        (measured 2026-08-16, Windows Debug + Release, Linux)
add_executable(p2p_replayguard p2p_replayguard.cpp)
_mscs_test_common(p2p_replayguard)
target_link_libraries(p2p_replayguard PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_replayguard COMMAND p2p_replayguard 7828)
set_tests_properties(p2p_replayguard PROPERTIES
    TIMEOUT 120 RESOURCE_LOCK loopback_7828 LABELS security)

# p2p_revokedist: the gate after p2p_keyrotate. That one proved a key can be
# withdrawn on a RUNNING hub; this asks how that fact TRAVELS. The list was a
# local file, so a compromised key was refused exactly where somebody remembered
# to type it - which for a mesh of any size is close to not being revoked.
#
# Six phases, and two of them are the design rather than the feature: phase 5
# applies a NEWER list naming nobody and requires the revocation to survive it
# (merged, never substituted - an arriving list may only ever ADD, or anyone
# handing a hub an old list could restore a compromised key), and phase 6
# requires a list from a valid stranger to be refused as RevErrIssuer, because
# a deny-list any peer can inject is a denial of service.
#   STATUS: PASSES        (measured 2026-08-16, Windows Debug + Release, Linux)
add_executable(p2p_revokedist p2p_revokedist.cpp)
_mscs_test_common(p2p_revokedist)
target_link_libraries(p2p_revokedist PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_revokedist COMMAND p2p_revokedist 7830)
set_tests_properties(p2p_revokedist PROPERTIES
    TIMEOUT 180 RESOURCE_LOCK loopback_7830 LABELS security)

# p2p_authchannel: the gate the THREAT MODEL found, not the fuzzer. Writing
# THREAT_MODEL.md (Targetcore ProductionPlan.md Stage 6 step 17) meant mapping
# every protection to the adversary it answers and to the line that enforces
# it, and two conditions that the documentation calls one switch turned out to
# be independent: KeyXWanted() ("my hub requires authentication") decides
# whether a connection runs the key agreement, and CanAuthSign() ("I hold an
# identity key") decides whether it signs its login.
#
# A hub with RequireAuth(false) that holds a key - the ordinary state of a peer
# provisioned for somewhere else in the tree - therefore signed a login it had
# no channel to bind to, and the verifying end accepted it: an AUTHENTICATED
# session in CLEARTEXT, on a server whose operator set RequireAuth(true). The
# channel binding that login kVersion 2 exists to carry was absent from the
# transcript at both ends, so the two null transcripts matched and verified.
#
# Three phases, one client key, one client address, and exactly one call
# different between phase 1 and phase 2. Phase 1 is the inline positive
# control and phase 3 the LIVENESS control - without it, a refused phase 2 is
# indistinguishable from a server that has fallen over.
#
# No WILL_FAIL: it asserts the fixed behaviour, and it was RED against the
# tree that had the defect and green against the same tree one condition later.
#   STATUS: PASSES        (measured 2026-08-20, Windows Debug)
add_executable(p2p_authchannel p2p_authchannel.cpp)
_mscs_test_common(p2p_authchannel)
target_link_libraries(p2p_authchannel PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_authchannel COMMAND p2p_authchannel 7836)
set_tests_properties(p2p_authchannel PROPERTIES
    TIMEOUT 180 RESOURCE_LOCK loopback_7836 LABELS security)

# p2p_gcmdirection: the session cypher holds TWO keys, one per direction, so the
# key a peer seals with is never the key it opens with, and sealing REFUSES once
# a key has been used its budget of times
# (Targetcore_ProdDocs/OpenCodeWork.md item 1, stages 1 and 2).
#
# The nonce is 96 bits and RANDOM, so NIST SP 800-38D section 8.3 bounds a key at
# 2^32 invocations, past which a collision stops being negligible - and a GCM
# nonce collision leaks the XOR of two plaintexts AND exposes the GHASH subkey.
# One key shared by both ends spent that budget from both ends at once and
# neither could count the other's draws. Split, each key has exactly one writer,
# which is what makes the count in stage 2 authoritative.
#
# Phases 1-5b drive P2PeerioGcm directly and need no socket; phase 6 stands up two
# authenticated hubs and moves traffic BOTH ways, which is the only phase that
# runs KeyXDerive - and therefore the reason this is labelled `security` rather
# than left in unit_suite, which the sanitiser gate does not run.
#
# No WILL_FAIL: it asserts the fixed behaviour. Proven RED first, twice - with the
# single-key derivation reinstated it fails 9 of 22 checks including both socket
# checks, and with the budget comparison disabled it fails 2 of 22.
#
# PHASE 6 OWNS TWO SpawnHub() HANDLES AND MUST CLOSE THEM. CloseHub() waits for the
# pump thread to LEAVE but is documented not to touch the handle - "IT ONLY READS THE
# MEMBER" (P2PeerHub.cpp:493). On Linux the handle owns a P2PThreadImpl holding the
# std::thread, and CloseHandle is what joins-or-detaches it and frees that
# (Platform/p2pthread.h:221-230). The first version omitted it and passed all 22 checks
# on every Windows configuration while failing BOTH Linux sanitisers - TSan `thread
# leak` twice, LSan 160 bytes in 6 allocations, same two lines. Windows sees only a
# handle leak at exit and nothing in the matrix looks for one. Fourth instance of the
# harness mistake a8108cd is about; same fix, wait then close.
#   STATUS: PASSES        (measured 2026-09-19: Windows Debug + Release, Linux GCC,
#                          and the whole security label at 39/39 under BOTH Linux
#                          TSan and Linux ASan+UBSan+LSan, nothing excluded)
add_executable(p2p_gcmdirection p2p_gcmdirection.cpp)
_mscs_test_common(p2p_gcmdirection)
target_link_libraries(p2p_gcmdirection PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_gcmdirection COMMAND p2p_gcmdirection 7859)
set_tests_properties(p2p_gcmdirection PROPERTIES
    TIMEOUT 180 RESOURCE_LOCK loopback_7859 LABELS security)

# p2p_authposture: can a RUNNING hub be asked whether any of this is ON?
# Targetcore ProductionPlan.md F-S6-2, THREAT_MODEL.md asset S9, and the gate
# for the fix.
#
# Stage 4 step 13 put load and occupancy into the hub snapshot and p2p_hubsnap
# keeps them there. NEITHER snapshot carried a security fact: not whether the
# hub requires authentication, not whether it holds a key at all, not whether
# a revocation list is loaded, not whether THIS connection authenticated, not
# as whom, and not whether its cypher is installed. A deployment could confirm
# its own posture only by reading the library's source.
#
# F-S6-1 is what that costs. For two days "this hub requires authentication"
# and "this connection is encrypted" were different facts on the same hub and
# nothing could have reported it; it was found by writing a threat model, which
# does not run on every build. This does.
#
# The monitor touches nothing but the two public Serialise() calls - reaching
# into IsAuthRequired() would prove the accessor works, which was never in
# doubt, instead of that the SNAPSHOT carries it. Five phases, and three of
# them exist only to stop a constant from passing: auth-off and auth-on must
# read DIFFERENTLY (the trap PumpsMax sat in for years), intent and capability
# must read SEPARATELY (the F-S6-1 shape), and an unauthenticated connection
# must report all four of its fields as absent proof.
#
# Two ports: the authenticated pair on the first, the open pair on the second.
#   STATUS: PASSES        (measured 2026-08-20, Windows Debug)
add_executable(p2p_authposture p2p_authposture.cpp)
_mscs_test_common(p2p_authposture)
target_link_libraries(p2p_authposture PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_authposture COMMAND p2p_authposture 7838)
set_tests_properties(p2p_authposture PROPERTIES
    TIMEOUT 180 RESOURCE_LOCK loopback_7838 LABELS security)

# p2p_confchannel: is the cypher CONSULTED, or only INSTALLED?
# Targetcore ProductionPlan.md F-S6-3, THREAT_MODEL.md, and the gate for the
# fix. The sibling of p2p_authchannel: that one asks whether a hub that
# requires authentication requires the CHANNEL it authenticated on; this one
# asks whether it requires the TRANSPORT to use the key it agreed.
#
# The cypher hooks live in P2Peerio::SendP2PeerMsg/RecvP2PeerMsg, so whether a
# transport encrypted anything depended on which subclass its factory happened
# to construct. P2PeerioDmx overrides both and consults neither and is RIGHT to
# - a pointer handoff inside one process has no wire. P2PeerioBSTR does the
# same with none of the justification. Nothing constructs it, which is what
# made it a trap rather than a bug: the first transport wired to it would have
# been plaintext on a hub reporting RequireAuth(true), and F-S6-1's fix cannot
# see that - the agreement completes, the cypher IS installed, the override
# simply does not consult it.
#
# Five phases. Phase 0 is in-process and asserts what each io class DECLARES
# about itself, because the gate reads exactly those two answers. Phases 1 and
# 4 are the stock controls. Phase 2 runs the offending declaration on an OPEN
# hub where no cypher exists to ignore, and must deliver - without it, phase
# 3's refusal is indistinguishable from an io class that cannot talk. Phase 3
# is the gate, one call different from phase 2.
#
# The verdict for phase 3 is the refusal ITSELF, matched out of the process
# diagnostic stream through P2Pevent::SetTextSink, and not merely a payload
# that failed to arrive - a phase 3 stopped by anything else reports
# INCONCLUSIVE rather than green. That is step 17's lesson written into the
# harness: measure the decision, not a consequence of the decision.
#
# Two ports: the authenticating pair on the first, the open pair on the second.
#
# No WILL_FAIL: it asserts the fixed behaviour, and it was falsified in both
# directions and once per enforcement - disabling the KeyXDerive gate makes
# phase 3 deliver, disabling the Send() refusal makes phase 5's cleartext frame
# reach the wire and be refused by the peer's decrypt instead.
#   STATUS: PASSES        (measured 2026-08-20: Windows Debug and Release,
#                          Windows MSVC ASan, Linux, and Linux ASan+UBSan+LSan
#                          with detect_leaks=1)
add_executable(p2p_confchannel p2p_confchannel.cpp)
_mscs_test_common(p2p_confchannel)
target_link_libraries(p2p_confchannel PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_confchannel COMMAND p2p_confchannel 7840)
set_tests_properties(p2p_confchannel PROPERTIES
    TIMEOUT 180 RESOURCE_LOCK loopback_7840 LABELS security)

# p2p_linktrust: is what a link may SKIP decided by what its transport can
# VOUCH FOR, and does a relaxation stay inside the class it was granted to?
# Targetcore securityRevision.md §8.2 steps 1-4, and the gate for them.
#
# Every security switch in the tree was a property of the HUB, so a DMX
# connection - a pointer handoff between two objects on one heap - ran a full
# ECDH agreement, held a BCrypt key object P2PeerioDmx never consults, and put
# four ECDSA operations on its login, to protect a channel with no wire. The
# only way to say otherwise was RequireAuth(false), which opens EVERY link the
# hub will ever hold. The fix splits the question: the transport declares a
# trust class (a fact, a virtual, nothing AcceptSpawn can drop), the hub keeps
# the policy per class, and P2PeerConTrust_Wire cannot be opened at all.
#
# Eleven phases. Phase 0 is in-process and asserts what each connection class
# DECLARES, because the gate reads exactly those answers - and the demotion
# algebra beside it, because "tightens only" is the property that makes an
# operator override safe to have. Phases 1 and 4 are the DMX and TCP positive
# controls. Phase 2 is the feature. Phase 3 is the F-S6-1 regression - the two
# ends reading different halves of one switch - and is the phase that was
# written first.
#
# Phases 5 and 6 are a pair and 6 is the reason the pair exists: 6 is 5 plus
# ONE call, DemoteTrust(Wire) on the service before it is posted, and it fails
# unless AcceptSpawn carried that ceiling to the accepted child. That single
# copied field is the one line in the whole feature a maintainer can forget,
# and phase 5 is what makes 6's refusal attributable to it rather than to a
# transport that stopped working.
#
# Phases 7 and 8 are step 3 and neither dials anything. 7 offers a fenced hub a
# Wire socket, a Local socket and a DMX connection and reads three return values
# out of PostP2PeerCon, then offers the same Wire socket to a hub that differs
# by the single RequireTrustAtLeast call - without that control the refusals are
# not attributable to the fence. 8 walks an entirely UNPROVISIONED hub through
# six combinations of fence and per-class policy: it must arm, as
# ArmNotRequiredByPolicy, exactly when it has a fence AND every class at or
# above that fence is open, and its last reading is the one that catches the
# wrong implementation - both relaxable classes open with NO fence must still
# refuse, because a socket can still be posted to a hub that has not fenced one
# out.
#
# Phases 9 and 10 are step 4 and they are LIVE: a real named pipe, dialled, with
# the class read off the connection that holds the handle rather than off a
# setting. 9 leaves the service at its new default and the accepted child must
# read Local - which is what pins the derivation, since m_bPipeLocal is computed
# back out of the pipe mode and the security attributes CreateNamedPipe was
# actually given, so deleting either PIPE_REJECT_REMOTE_CLIENTS or the explicit
# descriptor reddens it. 10 asks for P2PeerConPipeAccess_Legacy - the
# pre-revision call, byte for byte, kept reachable because a deployment sharing
# a pipe between two accounts must be able to keep working - and that pipe must
# read Wire and authenticate in full even though its hub opened the Local class.
# That is securityRevision.md §8.3's phase 6, and it is a live phase now rather
# than a row in phase 0.
#
# NO PORT AND NO RESOURCE_LOCK FOR THE PIPE PHASES, because a pipe name is not a
# port: it is machine-wide, so the test builds \\.\pipe\p2p_linktrust_<pid>_<n>
# and carries the only thing ctest guarantees is distinct between two concurrent
# copies of a suite. Adding it to the lock list would say something untrue about
# what the lock protects.
#
# SIX consecutive ports and not three. Three are dialled, one per live TCP
# phase, so a phase that leaves a socket in TIME_WAIT cannot make the next one
# look like a refusal. The other three belong to phase 7 and only one of them is
# ever bound - the two the fence refuses never reach a socket - but they are
# locked anyway, because a port this test names and a port this test binds have
# to be the same list or the next person to add a phase will find out which by
# a flake. A HUB ADDRESS PER PHASE for the same reason one level up: the phases
# each build and tear down hubs, and reusing addresses made every phase depend
# on the previous one's deregistration having completed in the process-wide
# registry. That cost a flake -- one failure in a full ctest run whose wall time
# was 40% above the run before it, and none in isolation -- before the addresses
# were split. The sleep that used to stand in for it is still there and is no
# longer what the test rests on.
#
# TIMEOUT 720 and not 240: the positive controls wait 30 s each because a
# control that times out reports a failure of the thing under test, and this
# runs beside thirty-six other suites on a machine whose load it does not
# control. The worst-case sum of the phase waits is ~240 s with the two pipe
# phases added; phases 7 and 8 add no waits, only four hub spawns.
#
# NOT WILL_FAIL: it asserts the behaviour steps 1-4 give. All nine phases of
# securityRevision.md §8.3 are covered; §8.4's measurement (step 5) is
# p2p_linkcost, below, and is not a gate test.
#
#   STATUS: PASSES
#
# READ THAT AS "the verdict this test gives WHEN IT REACHES ONE", because this
# one needs the qualification and the others do not. It inherits an OPEN defect
# it did not cause -- incidental finding 7 in Targetcore's
# securityRevision_progress.md -- which kills the process in a live TCP phase,
# intermittently, at a rate measured as high as one run in two on one machine.
# It was re-measured on the baseline commit with this pass's work stashed and it
# fires there too, in phases this work does not touch; it is in the connection
# registry / hub teardown path.
#
# So a red run here is READ, not believed: a run that printed a RESULT: line is
# a real verdict and the line above is what it should say, a run that printed
# *** TERMINATE is finding 7, and a run that stopped mid-phase with neither is
# finding 7 on a build predating the report hook. The evidence, and the three
# questions closing it wants answered, are under "The flake" in that file.
add_executable(p2p_linktrust p2p_linktrust.cpp)
_mscs_test_common(p2p_linktrust)
target_link_libraries(p2p_linktrust PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_linktrust COMMAND p2p_linktrust 7853)
set_tests_properties(p2p_linktrust PROPERTIES
    TIMEOUT 720
    RESOURCE_LOCK "loopback_7853;loopback_7854;loopback_7855;loopback_7856;loopback_7857;loopback_7858"
    LABELS security)

# p2p_linkcost: what does a POSTURE cost a message? securityRevision.md §8.4,
# which is §8.2 step 5, and it is a MEASUREMENT and not a gate.
#
# §8.4 asked for one run of dmx_mesh extended to three in-process hubs in a
# chain, N messages of a fixed size, under four postures - everything off,
# RequireAuth only, plus attestation, plus seal - reporting messages per second
# and CPU time per message. It exists because nothing in the tree times the
# security path: §3's figures are OPERATION COUNTS, and the §6.3 end-to-end
# waiver was explicitly deferred until there were numbers to decide it on.
#
# A FIFTH POSTURE was added and could not have been asked for before step 2:
# the default posture with SetLinkPolicy(InProcess, Open) on all three hubs.
# That is what §6.2 already ships, so it separates the cost §6.2 has ALREADY
# recovered from the cost only §6.3 could - which is §8.4's own closing
# question, "or whether §6.2 alone recovers what matters".
#
# NO TIMING ASSERTION, AND THAT IS DELIBERATE. A messages-per-second threshold
# in ctest is a flake on a build machine whose load this suite does not control,
# and this harness exists to produce a number for a document to argue over. The
# verdict is DELIVERY: exit 3 if any posture failed to deliver every message
# within its timeout, because a posture that quietly dropped its traffic would
# otherwise post the best throughput in the table.
#
# NO PORT AND NO RESOURCE_LOCK: every link is P2PeerConDmx - a pointer handoff
# between two objects on one heap. There is no socket, no pipe and no OS handle
# on the path, which is also the reason this is the right shape to measure: §6.3
# is about a destination in THIS PROCESS, so any cost measured here is paid for
# a threat that has no way in. A HUB ADDRESS AND A DMX SERVICE NAME PER POSTURE,
# for the reason spelled out above p2p_linktrust: the postures each stand three
# hubs up and tear them down, and both registries they use are process-wide.
#
# TIMEOUT 900. Five postures at N=4000, and the two that seal do public-key work
# per message in both directions; the primitives pass adds four more loops. The
# default N is small enough to keep a ctest run honest and can be raised on the
# command line when the numbers themselves are the point:
#   p2p_linkcost 20000 1024
add_executable(p2p_linkcost p2p_linkcost.cpp)
_mscs_test_common(p2p_linkcost)
target_link_libraries(p2p_linkcost PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_linkcost COMMAND p2p_linkcost)
set_tests_properties(p2p_linkcost PROPERTIES
    TIMEOUT 900
    LABELS measure)

# p2p_e2ewaive: securityRevision.md §6.3 - the END-TO-END waiver, which is the
# switch p2p_linkcost's measurement was taken to decide. §6.2 (SetLinkPolicy)
# recovers ~0 per message because the two end-to-end protections are not
# properties of a link; this is the only switch that reaches the 93%.
#
# It is also the one setting in the library whose correctness rests on a
# DEPLOYMENT ASSUMPTION rather than a mechanism - in-process hubs form one
# address subtree - so the gate cannot assert the assumption and does not
# pretend to. What it asserts is the two mechanical things around it:
#
# Phase 0 is the security-critical one: IsP2PmsgHubInProcess() matches an
# address EXACTLY. A hub Alice held here says nothing about Alice.Bob, which
# may be a child hub on another host, and a TRUE for a sub-address would waive
# the seal on precisely the traffic that leaves the machine. The phase asserts
# the sub-address, two-levels-below, prefix, sibling, empty and null cases, and
# that the answer goes back to FALSE when the hub is destroyed.
#
# Phases 3 and 4 are the enforcement and they are a PAIR, one switch apart. The
# observable is DELIVERY, not timing: Alice requires sealing and her allow-list
# entry for Carol carries an identity and no agreement key, so
# SealAppMsgOutbound must refuse to send. Waiver off, nothing arrives; waiver
# on with Carol a hub in this process, the same message arrives.
#
# NOT COVERED, and it is in the file's header too: an out-of-process
# destination behaviourally (it needs a second PROCESS - the whole point of the
# predicate is that no address this harness can invent distinguishes the two),
# and the attestation half on the receive side (GateRelayInbound is never
# reached in a chain, because the relay is a common ancestor of both ends -
# securityRevision_progress.md finding 11).
#
# NO SOCKETS, so no RESOURCE_LOCK and no port. Per-phase hub addresses, which
# is p2p_linktrust's lesson applied before it could cost anything.
#
# No sockets is also why this one carries no qualification where p2p_linktrust
# carries a long one: finding 7 lives in the live TCP path, and this test never
# enters it.
#   STATUS: PASSES
add_executable(p2p_e2ewaive p2p_e2ewaive.cpp)
_mscs_test_common(p2p_e2ewaive)
target_link_libraries(p2p_e2ewaive PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_e2ewaive COMMAND p2p_e2ewaive)
set_tests_properties(p2p_e2ewaive PROPERTIES
    TIMEOUT 180 LABELS security)

# p2p_fuzzframe: the FUZZ HARNESS for the framing path (Ahtung_Disaster.md,
# Track B item 5). C1 — the pre-auth heap overflow from an undersized wire
# length field — lived in P2Peerio::RecvP2PeerMsg stage 2, and ONE lower-bound
# check there closed FOUR findings. That is the signature of a parser nobody has
# swept, so this sweeps it: a 14-case seed corpus (the literal C1 input, both
# size bounds and their off-by-ones, the memmove re-sync and its recovery,
# split / coalesced / truncated streams, a byte-swapped header, and forged
# VBHeapRoot block links) with a seeded mutation loop on top of each case.
#
# No socket, no port, no RESOURCE_LOCK: stages 0-4 are driven in-process against
# the shipping parser. P2Peerio::Recv throws on bQueued before it touches m_pCon
# or ReadFile (P2Peerio.cpp:573-579), so the harness supplies the bytes itself,
# exactly as the IOCP completion would.
#
#   *** EXPECTED TO FAIL: 7893 findings, exit 1. That is the finding, not a
#       broken test. ***
#
# --strict-assert IS REGISTERED BELOW, ON PURPOSE. Without it the harness exits
# 0 while tripping 7891 ASSERTs, because an assert is otherwise a printed
# diagnostic rather than a verdict. Measured 2026-08-14, Debug, both ways:
#
#   p2p_fuzzframe 0x5EEDF00D 200
#     totals: message=293 refused=1482 starved=994 stalled=0 budget=45
#             ESCAPED=0 abandoned=0   asserts=7891
#     RESULT: PASS - 2814 frames, no crash, no hang, no escaped exception
#
#   p2p_fuzzframe 0x5EEDF00D 200 --strict-assert
#     RESULT: FAIL - 7893 finding(s), seed 0x5EEDF00D.   (exit 1)
#
# The first command is what used to be registered here, and it is why this test
# read GREEN for as long as it did. "No crash, no hang, no escaped exception" is
# a weaker claim than it looks: each of those 7891 asserts is wire data
# violating an invariant the code believes about its own image, reached
# PRE-AUTH. Registering the weaker command made ctest agree with itself and tell
# nobody anything, which is the exact failure mode the no-WILL_FAIL rule exists
# to prevent - reached by a different route.
#
# The two ORIGINAL defects below ARE fixed. `stalled=0` is the non-terminating
# block walk being bounded, and the documented repro now refuses cleanly:
#     p2p_fuzzframe 0x5EEDF00D --replay 9 1   ->  outcome=refused, asserts=0
# The assert POPULATION behind them was what stayed red, and it is closed as of
# 2026-08-21 - the baseline below is 0. See the block above it for what closed
# it and for the before/after figures that show it was closed rather than
# muted.
#
# It found two defects on its first run, both in Msgcore/MsgVBHeap.cpp, both
# reached PRE-AUTH, and both stepping on wire-supplied values:
#   (1) a NON-TERMINATING walk - `aVBLock += VBHeap_Sizenn(pVBLock)` (:1591)
#       never advances when a forged block header declares size 0, so the
#       `while (aVBLock < nSizeofAlloc)` at :1572 never ends;
#   (2) an ACCESS VIOLATION - the free-list walk dereferences a wire-supplied
#       link at :1322-1323 before any range check.
#       Reproduce: p2p_fuzzframe 0x5EEDF00D --replay 9 1
# Both validators USED TO BE ASSERT-wrapped at the CreateIOMAGE call site this
# path reached, so a Release build did not take these paths from here - it
# accepted the forged chain unwalked instead, which is not obviously better.
# That is the half of the finding that was a security defect rather than a noise
# problem, and closing it is what the receive path's length argument does. See
# the harness banner.
#
# Same rules as the gate tests above: no WILL_FAIL - that would make CI green
# on an open defect and then turn red the day somebody fixes it.
#
# AND THE ASSERT BUDGET BELOW IS NOT WILL_FAIL BY ANOTHER NAME. The difference
# is what happens on a fix. WILL_FAIL INVERTS the verdict: the test is green
# while broken and goes RED the day it is repaired, which is why it is banned
# here. The budget inverts nothing - it changes the proposition from "no assert
# trips" to "no MORE assert trips than were recorded", which is a weaker claim
# honestly stated. Fix the defect and the count falls: still green, plus a
# RATCHET line telling you to tighten the baseline. Every other verdict is
# untouched - an ESCAPED frame, a crash, a hang or a stall is a hard failure at
# any assert count.
#
# The other 12 cases pass, so the harness still earns its keep as the REGRESSION
# GUARD on P2Peerio.cpp:433 — four lines that closed four findings and that
# nothing else in the tree pins.
#
# The seed is FIXED here on purpose: a red CI run must be reproducible from the
# printed seed alone, and any single case+iteration replays with
#   p2p_fuzzframe 0x5EEDF00D --replay <case> <iter>
# Vary the seed or raise the per-case iteration count by hand for a soak run;
# the registered test stays short. KEEP THE TIMEOUT: the harness's own drive
# loop is provably finite, so a hang can only be inside the parser's re-sync
# loop, and ctest is the only thing that can see it.
# THE ASSERT BUDGET (ProductionPlan.md Stage 1 step 4). IT IS BACK AT ZERO, AND
# THIS TIME BECAUSE THE DEFECT IS GONE RATHER THAN BECAUSE NOBODY HAD LOOKED.
#
# It was registered with --strict-assert once before, which fails on ANY tripped
# assert, and it was permanently red: 7,082 on Windows. A suite with a standing
# red trains people to stop reading red, which costs more than the finding the
# red was advertising - and a zero-tolerance gate cannot answer the only useful
# question about a number that size, which is "same known population, or did
# somebody just make it worse?" So from 2026-08-18 the tally was a TRACKED
# NUMBER against a recorded baseline, and the harness said on every green pass
# that the finding was still open.
#
# From 2026-08-21 the baseline is 0 on both platforms. The mechanism is
# unchanged - at or under is green, over is a REGRESSION and fails - and the
# proposition it now carries is the strong one again: no wire datum reaches a
# check meant for this library's own heaps.
#
# THE BASELINES WERE MEASURED, NOT CHOSEN, and they differed per platform
# because the platforms do not reach the same depth: glibc's assert aborts, so
# the POSIX trap ABANDONS the input where Windows continues past the violated
# invariant. That showed up as asserts == abandoned on Linux (796 == 796) and is
# exactly the asymmetry ProductionPlan.md Stage 2 step 7 is about - 796 against
# 7,082 never meant Linux was nine times safer.
#
#   Windows  7082   measured 2026-08-18, Debug (was 7,893 on 2026-08-14)
#   Linux     796   measured 2026-08-18, gcc Debug; message=136 vs Windows 315
#   both         0  measured 2026-08-21, over 3,618 inputs -- ONE REGISTERED RUN
#   both         0  measured 2026-09-02, over 976,860 inputs / 270 rounds / 902 s
#
# AND A BASELINE IS ONLY GOOD FOR THE CAMPAIGN LENGTH IT WAS MEASURED OVER,
# which is why those two rows now carry one. The 2026-08-21 zero was honest and
# it was also misleading, and both at once: on 2026-09-01 a 116-round campaign
# tripped 243 asserts, ALL AT ONE SITE (Msgcore/P2PmsgVBLock.cpp:1004), reached
# about once in 1,700 pre-auth framing inputs. A 3,618-input run expects about
# two of those and saw none, so "the assert population is closed" was a true
# statement about 3,618 inputs and a false one about the code. The defect is
# fixed (Msgcore, 2026-09-02) and the row above is the re-measurement -- but the
# lesson outlives it: THE NUMBER OF INPUTS IS PART OF THE CLAIM. A zero quoted
# without one is a zero of unknown strength, and this comment spent eleven days
# being read as the strong kind.
#
# RAISING A BASELINE TO CLEAR A RED IS THE ONE THING THIS MUST NOT BE USED FOR,
# and with the baseline at 0 that is the only direction left to raise it in. If
# the count goes up, something widened what hostile wire data can reach; say
# what changed and why it is acceptable, in the commit. The harness prints a
# RATCHET line when the count falls, which is what walked 89,901 down to 0.
#
# THESE TWO NUMBERS WERE NEVER ON THE SAME SCALE, and they sat next to each
# other here, which is exactly the comparison ProductionPlan.md Stage 2 step 7
# exists to prevent. 796 against 7082 did not mean Linux was safer; it meant
# Linux ran a shallower test. A Windows assert is counted and execution
# CONTINUES past the violated invariant, so one input can trip many. Off Windows
# glibc's noreturn __assert_fail leaves the interposed trap no way back, so the
# input is ABANDONED at the FIRST assert it trips - measured, 2026-08-18:
# Windows covered 2814/2814 inputs to the end of the parse, Linux 2018/2814.
#
# Each baseline is therefore only ever compared with ITSELF, on its own
# platform. The harness tags every figure it prints with its depth model
# (totals[win-crt-continue] / totals[posix-assert-trap]) so the two cannot be
# lined up even by accident. BOTH ARE NOW ZERO, and they are still two separate
# numbers for that reason: the day one of them has to move, the other must not
# move with it by accident.
#
# BOTH BASELINES WENT TO ZERO ON 2026-08-21, AND THE POPULATION IS CLOSED.
#
#   Windows  89901 -> 0        Linux  1044 -> 0
#
# What closed it is in Msgcore and Targetcore, not here, and it is two changes:
#
#   1. P2Peerio.cpp stage 4 passes the RECEIVED LENGTH into the P2PeerMsg
#      constructor, so an arriving image is adopted through
#      P2PmsgHeap_CreateIOMAGE(pIOmage,nBufferLen). The pointer-only overload it
#      used before ends in
#          ASSERT(P2PmsgHeap_AssertValidIOMAGE(pHandle));
#          ASSERT(P2PmsgHeap_AssertVBlocksIOMAGE(pHandle));
#      - both block walks INSIDE the assertion. A Release build therefore did
#      not run a reduced check, it ran NONE, and adopted a forged block chain
#      unwalked. The length-validated overload walks it in every build and
#      refuses on the answer.
#
#   2. MsgVBHeap's UNTRUSTED GATE separates the two jobs those walks do. Over a
#      heap this process built, a violated invariant is a bug here and ASSERT is
#      right. Over an image a stranger sent it is the ordinary case, and the
#      answer is to refuse. Inside a gate the walks refuse quietly, stop at the
#      first bad block, and do not write the image's root back into agreement
#      with itself on the way past - that last one being a validator writing to
#      the bytes it was asked to judge.
#
# THE EVIDENCE THAT THIS IS A FIX AND NOT A SILENCER, measured on the same 3618
# frames, same seed, same iteration budget:
#
#                       message   refused   starved   asserts
#   before, Debug           548      1819      1185     89896
#   before, Release         550      1817      1185         0 (ASSERT compiled out)
#   after,  Debug           246      2140      1174         0
#   after,  Release         246      2140      1174         0
#
# 304 forged frames that a RELEASE build used to turn into P2PeerMsg objects are
# now refused. And the two builds now agree to the frame, where before they
# differed by two - because the Debug-only root fixups WROTE to the image they
# were judging and changed its fate. A gate that had merely been muted would
# have left the message and refused columns exactly where they were.
#
# `limit_exact` tripping ZERO was the tell, and it is worth keeping now that
# every case reads like it: it is a header-only vector that starves in stage 3
# and never reaches the block walk, so it added coverage without adding
# asserts - "what the other three would look like if the finding were closed",
# as the note here said on 2026-08-20. They do.
if(WIN32)
    set(_p2p_fuzz_assert_baseline 0)   # 2026-08-21, Debug; was 89901
else()
    set(_p2p_fuzz_assert_baseline 0)   # 2026-08-21, gcc Debug; was 1044
endif()
#   STATUS: PASSES CLEAN  (measured 2026-08-21, Windows Debug + Release)
#           Was PASSES-WITHIN-BUDGET, and before that EXPECTED-FAIL. This time
#           the DEFECT changed, not the gate. See above.
add_executable(p2p_fuzzframe p2p_fuzzframe.cpp)
_mscs_test_common(p2p_fuzzframe)
target_link_libraries(p2p_fuzzframe PRIVATE targetcore msgcore p2pplatform)
if(NOT WIN32)
    # ENABLE_EXPORTS puts -rdynamic on the link, which is what lets this
    # executable's __assert_fail reach .dynsym and INTERPOSE libc's for the
    # calls made inside libmsgcore.so / libtargetcore.so. That is the whole
    # POSIX assert trap: without it the harness dies on the first ASSERT any
    # input trips and has never fuzzed anything on Linux. Measured rather than
    # assumed - with the attribute but without this, `nm -D` showed the symbol
    # absent from the dynamic table and the run still aborted at case 0
    # iteration 0. The harness also marks the definition
    # __attribute__((visibility("default"))), because the tree builds
    # -fvisibility=hidden; BOTH are required.
    set_target_properties(p2p_fuzzframe PROPERTIES ENABLE_EXPORTS ON)
endif()
# --corpus is a SOURCE-tree path and --repro-dir a BUILD-tree one, and the
# asymmetry is deliberate: a corpus is an input that people add to and commit,
# a reproducer is an output and must never be written into the source tree by a
# test run. Refer MscsUnitTests/fuzz/README.md.
add_test(NAME p2p_fuzzframe COMMAND p2p_fuzzframe 0x5EEDF00D 200
         --assert-baseline ${_p2p_fuzz_assert_baseline}
         --corpus     ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus
         --repro-dir  ${CMAKE_CURRENT_BINARY_DIR}/fuzz-repro)
set_tests_properties(p2p_fuzzframe PROPERTIES TIMEOUT 300 LABELS security)

# LEAK DETECTION IS OFF FOR THIS TEST ONLY, and that is not a concession.
#
# ProductionPlan.md Stage 1 step 5 ran the suite under ASan+UBSan+LSan for the
# first time. Everything else came back leak-clean; this harness reported
# 1.76 MB in 1694 allocations, from two causes, both of which are properties of
# the harness rather than of the library:
#
#   1. The harness LEAKS ON PURPOSE. p2p_fuzzframe.cpp (see the comment above
#      `bool bStage4`) declines to free pUserDB2 when a throw out of
#      `new P2PeerMsg(image)` leaves ownership genuinely ambiguous, "rather than
#      risk a double free being mistaken for a fuzz finding". That is the right
#      call for a fuzzer and it is deliberate, so LSan is measuring a decision.
#
#   2. The POSIX assert trap unwinds out of library frames. Every input that
#      trips an ASSERT abandons the case from inside RecvP2PeerMsg, so the
#      library's own cleanup never runs. Measured: leaked allocations track the
#      abandoned count linearly (84 abandoned -> 173 allocations, 796 -> 1694,
#      ~2.1 each), which is what "one per abandoned case" looks like. It is an
#      artefact of the Linux trap, and it is why the Windows run -- where the
#      _CRT_ASSERT hook returns and continues -- shows abandoned=0.
#
# A suppression file was the obvious alternative and is worse: the two stacks
# run through P2Peerio::RecvP2PeerMsg and P2PmsgHeap_CreateIOMAGE, so an entry
# broad enough to cover them would silently cover most of the receive path, and
# a real leak there is exactly the thing worth catching. Turning the check off
# for one test, in the open, hides less than a suppression that looks narrower
# than it is. LSan stays ON for every other test in the suite.
#
# exitcode=23 is set explicitly rather than left to the default. DO NOT add
# halt_on_error=0 here or anywhere in CI: measured 2026-08-18, it makes LSan
# print a full leak report and still exit 0, which is a green tick over a leak.
set_tests_properties(p2p_fuzzframe PROPERTIES
    ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0:exitcode=23")

# p2p_fuzzblock: the FUZZ HARNESS for the AUTHENTICATED wire parsers.
# ProductionPlan.md Stage 6 step 16.
#
# p2p_fuzzframe attacks the FRAMING path and has since the C1-class finding.
# Nothing attacked the four parsers added after it - the login block, the ack,
# the relay attestation and the revocation list. What stood in for coverage is
# worth quoting because it sounds like coverage and is not: step 16 records
# "60k mutated inputs per change, BY HAND". A number produced by hand, once, is
# a measurement of the day it was taken.
#
# THE ORACLE IS STRONGER HERE THAN IN THE FRAMING HARNESS, and that is the
# reason this is a separate binary rather than more cases in that one. A
# mutated FRAME has no expected outcome, so p2p_fuzzframe can mostly only ask
# "did it crash, hang or escape". These four blocks are SIGNED, so it can ask
# the real question: ANY CHANGE TO A SIGNED BYTE MUST NOT VERIFY. Every mutant
# that comes back OK is a finding with no judgement required.
#
# The exception is handled rather than waved at: three of the four parsers test
# `cbIn <` a minimum rather than `cbIn ==`, so trailing bytes are ignored BY
# DESIGN and a mutation landing past the block proper is a legitimate no-op.
# The harness computes that boundary per target from the ORIGINAL block and
# applies the oracle only inside it. Getting that wrong the other way would be
# worse than having no oracle: a fuzzer that cries wolf gets switched off.
#
# It also checks the quiet half, which is where a leak lives rather than a
# crash: VerifyRelay's attester-name output must be EMPTY on every path that
# does not return AuthOk, or a caller ignoring the return value picks up an
# address the block merely claimed. The buffer is pre-poisoned with '#' so
# "left untouched" and "written empty" are distinguishable.
#
# POSITIVE CONTROLS FIRST, and the run reports SETUP rather than PASS if any
# fails. The provisioning is four keys, three allow-lists and three revocation
# files; any one of them silently not landing gives a rig that refuses
# everything, under which every mutant is "correctly refused" and the run goes
# green having measured nothing.
#
# IT SPAWNS NOTHING. AttestRelay, VerifyRelay, AuthBuildLogin, AuthVerifyLogin,
# IssueRevocationList and ApplyRevocationList all take only m_oCSectionHub, so
# a round costs a function call rather than a thread - which is what makes a
# per-change gate affordable and a soak run worth doing.
#
# SECURITY LABEL, and it needs no argument: these parsers are the login gate.
#   STATUS: PASSES        (measured 2026-08-20, Windows Debug + Linux)
add_executable(p2p_fuzzblock p2p_fuzzblock.cpp)
_mscs_test_common(p2p_fuzzblock)
target_link_libraries(p2p_fuzzblock PRIVATE targetcore msgcore p2pplatform)
# THE CORPUS IS PASSED AS A SOURCE-TREE PATH, not a staged copy. A corpus is
# meant to be added to - by a developer promoting a reproducer, and by the
# scheduled soak run - and a build-time copy would mean the gate replayed
# yesterday's corpus until someone reconfigured. --repro-dir lands in the build
# tree, because a reproducer is an OUTPUT and must not be written into the
# source tree by a test run.
add_test(NAME p2p_fuzzblock COMMAND p2p_fuzzblock 0x51CEB00D 400
         --corpus     ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus
         --repro-dir  ${CMAKE_CURRENT_BINARY_DIR}/fuzz-repro)
set_tests_properties(p2p_fuzzblock PROPERTIES TIMEOUT 300 LABELS security)


# p2p_expreg: the two residuals left by M2's Explorer half after the session-23
# downgrade. The premise ("reachable pre-auth") is dead and the registration
# path sits downstream of the source-binding gate, which is live at the stock
# posture - but that gate admits the logged-in identity OR an IsRable()
# descendant of it (P2PeerCon.cpp:2058, P2Peer.cpp:365-377), and On_P2PexpCtrl
# registers pMsg->GetSource() as it finds it (P2PeerExplorer.cpp:1277,1292). So
# a peer the Explorer assigned CEX.XC0 can register CEX.XC0.Ghost, and
# On_XCidConClose then reaps by the EXACT slot address (:1211-1219), never by
# prefix, so the fabricated entry is permanent - the registry has no other
# eviction path.
#
#   *** PASSES (measured 2026-08-14). Both residuals closed:
#       P2PexpReg_BindSource (P2PeerExplorer.cpp:202-217) folds any claimed
#       source back onto the address the Explorer ASSIGNED to the connection it
#       arrived on, and reaping now goes by prefix rather than exact slot. ***
#
# Same rules as the gate tests above: no WILL_FAIL, labelled `security`, and
# phases 1-2 are inline positive controls (the Explorer must assign a slot, and
# an HONEST registration must land) so a refusal is distinguishable from a dead
# registration path - both of those report exit 3 INCONCLUSIVE, not a pass.
#   STATUS: PASSES        (measured 2026-08-14, Windows Debug)
add_executable(p2p_expreg p2p_expreg.cpp)
_mscs_test_common(p2p_expreg)
target_link_libraries(p2p_expreg PRIVATE targetcore msgcore p2pplatform)
add_test(NAME p2p_expreg COMMAND p2p_expreg 7819)
set_tests_properties(p2p_expreg PROPERTIES
    TIMEOUT 60 RESOURCE_LOCK loopback_7819 LABELS security)

# seal_interop: the one test that fails if a Windows peer and a Linux peer cannot
# talk. Every other security test runs both ends on the SAME backend, so all of
# them stay green even if the two disagree on the wire. This opens bodies sealed
# by the other backend, from the vectors in vectors/, and checks the two places
# they could silently differ: the UTF-8 address transcript (wchar_t is 2 bytes
# here and 4 there, and the addresses are inside the GCM AAD and the signature)
# and the 96-byte X||Y||d private blob. Linux builds its half in
# Targetcore/CMakeLists.txt against the OpenSSL backend.
if(WIN32)
    #   STATUS: PASSES        (measured 2026-08-14, Windows Debug)
    add_executable(seal_interop seal_interop.cpp)
    _mscs_test_common(seal_interop)
    target_link_libraries(seal_interop PRIVATE targetcore msgcore p2pplatform)
    add_test(NAME seal_interop COMMAND seal_interop verify
        ${CMAKE_CURRENT_SOURCE_DIR}/vectors/seal_windows_cng.vec
        ${CMAKE_CURRENT_SOURCE_DIR}/vectors/seal_linux_openssl.vec)
    set_tests_properties(seal_interop PROPERTIES TIMEOUT 60 LABELS security)
endif()

if(NOT WIN32)
    # com232 needs a virtual null-modem: PTYs on Linux (built here); on Windows it needs the
    # external com0com COM-pair driver, so it stays Linux-only until that is wired.
    mscs_mesh_test(com232_mesh)   # RS-232/termios over a self-built virtual null-modem (PTYs)
    set_tests_properties(com232_mesh PROPERTIES TIMEOUT 60)

    # teardown_stress: mid-flight kill/teardown churn (§8, §5.6). Built (drive via
    # run_sanitizers.sh) but NOT gated — two teardown-robustness tails remain (§5.6).
    add_executable(teardown_stress teardown_stress.cpp)
    _mscs_test_common(teardown_stress)
    target_link_libraries(teardown_stress PRIVATE targetcore msgcore p2pplatform)

    # perf_ab: throughput+latency A/B (§8). Built for reproducibility but NOT gated (timing).
    add_executable(perf_ab perf_ab.cpp)
    _mscs_test_common(perf_ab)
    target_link_libraries(perf_ab PRIVATE targetcore msgcore p2pplatform)
endif()



# Runtime loader path for every test registered above. Must be LAST: it reads the
# directory TESTS property, so anything added after this line would not be covered.
_mscs_apply_loader_path()
