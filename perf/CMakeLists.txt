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
# ---------------------------------------------------------------------------
# MscsUnitTests/perf -- the P0 performance suite of p2p_performance.md §3.
#
# EVERY TARGET HERE IS LABELS measure, AND NONE IS A GATE. Timing is not a
# verdict on a machine whose load ctest does not control. Exit codes keep the
# tree's meaning: 0 ran, 1 a correctness check inside the bench failed (a
# primitive that silently failed would post the best number), 3 timeout.
# `ctest -L measure` runs the suite; `ctest -LE measure` keeps it out of a gate
# run. Headline numbers are RELEASE builds only (§3.2); a Debug run prints a
# warning in its box line.
#
# Each bench prints the perf_ab line dialect plus one `PERFJSON {...}` line per
# case and one `PERFBOX {...}` line per run; tools/perf/perf_run.py (solution
# root) interleaves runs and parses both.
#
#   B0 perf_floor     no MSCS code: thread handoff, loopback TCP, null syscalls
#   B1 perf_ab        two-hub loopback (registered one level up, ../perf_ab.cpp)
#   B2 msgcore_bench  Msgcore with no transport: build / serialize / adopt /
#                     lookup / MsgFieldRef / Vect / C-API, swept over N fields
#   B3 crypto_bench   every security-posture primitive, this platform's backend
#   B5 perf_fanout    one hub x C connections; relay chains of H hops
#   B8 msgstore_bench P2PmsgMgr as a store: populate / save / defrag / load
#                     / path lookups / triggers at 64 KB, 1 MB, 16 MB (P0b)
#
# Still to come (§3.1): B4 linkcost Wsa + CPU column, B6 perf_payload, B7
# cross-host run mode.
# ---------------------------------------------------------------------------

# B0 perf_floor -- links NOTHING from this tree, deliberately: it is the
# denominator. No port lock: it binds an ephemeral loopback port.
add_executable(perf_floor perf_floor.cpp)
target_compile_features(perf_floor PRIVATE cxx_std_23)
if(WIN32)
    # perf_floor is not an MFC program; the parent directory sets the flag for
    # the legacy-header harnesses.
    set_target_properties(perf_floor PROPERTIES MFC_FLAG 0)
    target_link_libraries(perf_floor PRIVATE ws2_32)
else()
    target_compile_definitions(perf_floor PRIVATE PERF_COUNT_ALLOCS)
    find_package(Threads REQUIRED)
    target_link_libraries(perf_floor PRIVATE Threads::Threads)
endif()
add_test(NAME perf_floor COMMAND perf_floor 20000)
set_tests_properties(perf_floor PROPERTIES TIMEOUT 300 LABELS measure)

# B2 msgcore_bench -- links msgcore + p2pplatform, nothing from Targetcore, and
# is built the way golden_utf16 is (_mscs_test_common: the suite's stdafx.h,
# Unicode, MFC on Windows). It needs the real msgcore target, so the CI
# parse-check (stub siblings) skips it.
if(TARGET msgcore AND TARGET p2pplatform)
    add_executable(msgcore_bench msgcore_bench.cpp)
    _mscs_test_common(msgcore_bench)
    target_include_directories(msgcore_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(msgcore_bench PRIVATE msgcore p2pplatform)
    add_test(NAME msgcore_bench COMMAND msgcore_bench 1)
    set_tests_properties(msgcore_bench PROPERTIES TIMEOUT 600 LABELS measure)

    # B8 msgstore_bench (P0b, p2p_performance.md §3.1a) -- P2PmsgMgr as a
    # store at 64 KB / 1 MB / 16 MB: populate, save, defragment, load, path
    # lookups, triggers. Same link scope as msgcore_bench (P2PmsgMgr is in
    # msgcore). Writes its files under the build tree and removes them. The
    # registration stops at 1 MB to keep a measure run short; the 16 MB row is
    # perf_run.py's job (no argument = all three).
    add_executable(msgstore_bench msgstore_bench.cpp)
    _mscs_test_common(msgstore_bench)
    target_include_directories(msgstore_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(msgstore_bench PRIVATE msgcore p2pplatform)
    add_test(NAME msgstore_bench COMMAND msgstore_bench 1024)
    set_tests_properties(msgstore_bench PROPERTIES TIMEOUT 600 LABELS measure)
endif()

# B5 perf_fanout -- one topology per process (the hub limit, MAX_P2PmsgHub =
# 256, is per process): `fan C` is one hub with C+1 children on one listener,
# `chain H` is H hops with H-1 relays. Two registrations, the ends of each
# sweep; the full sweep is perf_run.py's job. Ports 7860 (fan) and 7861.. (chain).
if(TARGET msgcore AND TARGET targetcore AND TARGET p2pplatform)
    add_executable(perf_fanout perf_fanout.cpp)
    _mscs_test_common(perf_fanout)
    target_include_directories(perf_fanout PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(perf_fanout PRIVATE targetcore msgcore p2pplatform)
    if(NOT WIN32)
        target_compile_definitions(perf_fanout PRIVATE PERF_COUNT_ALLOCS)
    endif()
    # 7860 is shared with p2p_ucastgate; the common lock name serialises them.
    # chain H uses H consecutive ports from 7861, so H=4 locks 7861-7864.
    add_test(NAME perf_fanout_fan COMMAND perf_fanout fan 64 500 10000)
    set_tests_properties(perf_fanout_fan PROPERTIES
        TIMEOUT 600 RESOURCE_LOCK loopback_7860 LABELS measure)
    add_test(NAME perf_fanout_chain COMMAND perf_fanout chain 4 500 10000)
    set_tests_properties(perf_fanout_chain PROPERTIES
        TIMEOUT 600 RESOURCE_LOCK "loopback_7861;loopback_7862;loopback_7863;loopback_7864" LABELS measure)
endif()

# B3 crypto_bench -- compiled the way crypto_kat and seal_interop are on Linux:
# the backend TU and the seal are built INTO the exe, because the AEAD / HKDF /
# HMAC symbols are internal to the Targetcore DLL. Targetcore_STATIC empties
# P2PCNG_EXT so nothing is dllimport'ed.
#
# Guarded by existence so the CI parse-check (stub siblings, no Targetcore
# sources) still generates.
set(_tc ${CMAKE_CURRENT_SOURCE_DIR}/../../Targetcore)
if(WIN32)
    set(_crypto_backend ${_tc}/P2PCngCrypto.cpp)
else()
    set(_crypto_backend ${_tc}/P2PCngCrypto_openssl.cpp)
    find_package(OpenSSL QUIET COMPONENTS Crypto)
endif()
if(EXISTS ${_crypto_backend} AND EXISTS ${_tc}/P2PeerSeal.cpp AND
   (WIN32 OR TARGET OpenSSL::Crypto))
    add_executable(crypto_bench
        crypto_bench.cpp
        ${_crypto_backend}
        ${_tc}/P2PIdentityStore.cpp
        ${_tc}/P2PeerSeal.cpp)
    target_include_directories(crypto_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${_tc}
                                                    ${_tc}/../Msgcore/Platform)
    target_compile_features(crypto_bench PRIVATE cxx_std_23)
    target_compile_definitions(crypto_bench PRIVATE Targetcore_STATIC)
    if(WIN32)
        # P2PCngCrypto.cpp includes Targetcore's stdafx.h, which is MFC; the
        # parent's CMAKE_MFC_FLAG 2 (shared MFC) applies. No counting operator
        # new here: MFC supplies its own and the DLLs carry theirs.
        target_compile_definitions(crypto_bench PRIVATE _UNICODE UNICODE WIN32 _WINDOWS)
        target_link_libraries(crypto_bench PRIVATE bcrypt ncrypt crypt32 advapi32)
    else()
        target_compile_definitions(crypto_bench PRIVATE PERF_COUNT_ALLOCS)
        target_link_libraries(crypto_bench PRIVATE OpenSSL::Crypto)
    endif()
    add_test(NAME crypto_bench COMMAND crypto_bench 1)
    set_tests_properties(crypto_bench PROPERTIES TIMEOUT 600 LABELS measure)
else()
    message(STATUS "perf: crypto_bench skipped (Targetcore crypto sources or OpenSSL not found)")
endif()

# perf_floor and crypto_bench load no MSCS DLL, so there is nothing for
# _mscs_apply_loader_path() to add today. It is called anyway, LAST, for the
# benches that will link msgcore/targetcore (B2, B5, B6): forgetting it then is
# the 0xc0000135 failure the root CMakeLists records twice. It is a no-op until
# msgcore/targetcore exist, so guard it the way it asks to be guarded.
if(TARGET msgcore AND TARGET targetcore)
    _mscs_apply_loader_path()
endif()
