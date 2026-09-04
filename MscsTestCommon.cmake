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
# MscsTestCommon.cmake — the compile shape every MSCS test harness needs, and
# the runtime loader path every registered test needs.
#
# Included by BOTH MscsUnitTests/CMakeLists.txt and
# MscsUnitTestsExternal/CMakeLists.txt. It exists because the suite was split in
# two on 2026-08-14 and the alternative was a second copy of this configuration
# in the new directory. A duplicated build shape drifts exactly like duplicated
# code does, and this tree has the scars: the vendored Platform that compiled
# only on one platform, the stale duplicate C wrapper in MSCS_JavaBindings, two
# divergent DH implementations. One copy, included twice.
#
# Paths are anchored on CMAKE_CURRENT_LIST_DIR (this file's directory,
# MscsUnitTests/) rather than CMAKE_CURRENT_SOURCE_DIR, so they resolve to the
# same siblings no matter which directory includes it.
# ---------------------------------------------------------------------------

set(_mscs_tests_root ${CMAKE_CURRENT_LIST_DIR})

# Include surface: the INCLUDING directory (its own sources), MscsUnitTests
# (stdafx.h, TestFramework.h — shared by both runners), the two library source
# dirs, and the platform shim (P2PWCHAR etc.). win-compat is the Linux-only
# generated windows.h forwarder; on Windows the real SDK/MFC headers are used.
set(_mut_includes
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${_mscs_tests_root}
    ${_mscs_tests_root}/../Msgcore
    ${_mscs_tests_root}/../TargetCore
    ${_mscs_tests_root}/../Msgcore/Platform)
if(NOT WIN32)
    list(APPEND _mut_includes ${_mscs_tests_root}/../Msgcore/Platform/win-compat)
endif()

# Common compile shape for a legacy-header-consuming harness.
function(_mscs_test_common name)
    target_include_directories(${name} PRIVATE ${_mut_includes})
    target_compile_features(${name} PRIVATE cxx_std_23)
    target_compile_definitions(${name} PRIVATE _UNICODE UNICODE)
    if(WIN32)
        target_compile_definitions(${name} PRIVATE WIN32 _WINDOWS)
        # The legacy inline headers reference _bstr_t/_variant_t (comsuppw[d]) + Winsock;
        # targetcore/msgcore link these PRIVATE, so a consumer exe needs its own copy.
        target_link_libraries(${name} PRIVATE
            ws2_32 MsWsock Propsys comsuppw$<$<CONFIG:Debug>:d>)
    else()
        # -fpermissive: the MSVC-lax member-pointer / address-of forms the legacy headers use.
        target_compile_options(${name} PRIVATE -fpermissive)
    endif()
endfunction()

# ---------------------------------------------------------------------------
# _mscs_apply_loader_path() WAS DEFINED HERE AND IS NOW DEFINED IN THE ROOT
# CMakeLists.txt (2026-09-04). Nothing that called it needs to change: it is the
# same name and the same behaviour, and a function defined at the root is visible
# in every directory added below it.
#
# It moved because THIS file is the wrong place for it and the second occurrence
# of the bug proved it. The loader path is needed by every directory that
# registers a test linking msgcore or targetcore; this file is included by
# MscsUnitTests and MscsUnitTestsExternal and by nothing else, because P2PeerWeb
# is its own component repository, is added BEFORE MscsUnitTests, and is guarded
# only by its own existence -- so it cannot include a file that may not be in the
# checkout, and it therefore had no loader path at all. All eleven p2pweb_w*
# tests were failing under a bare `ctest` at 0xc0000135, which is the same
# eleven-test, same-status-code failure the note that used to sit here recorded
# from 2026-08-13, in a second directory. The fix was shared; the place to put it
# was not.
#
# The full rationale -- multi-config genex, the per-platform variable name, and
# the stale-DLL-beside-the-exe trap that defeats all of it -- moved with the
# function and is at the root. Read it there before changing either.
# ---------------------------------------------------------------------------
