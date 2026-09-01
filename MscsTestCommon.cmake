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
    ${_mscs_tests_root}/../Platform)
if(NOT WIN32)
    list(APPEND _mut_includes ${_mscs_tests_root}/../Platform/win-compat)
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
# Runtime loader path — for EVERY test registered in the CALLING directory.
#
# msgcore and targetcore are the only SHARED targets involved, and this tree sets
# no unified CMAKE_RUNTIME_OUTPUT_DIRECTORY, so each lands in its own per-target
# build directory and never beside the test exe. A ctest run therefore only
# worked if the CALLER put those directories on the loader path first: a bare
# `ctest` came back with ELEVEN tests failing at 0xc0000135 (STATUS_DLL_NOT_FOUND),
# which looks exactly like a code regression and is not one.
#
# Two things this has to get right:
#   * MULTI-CONFIG. The Visual Studio generator appends $<CONFIG> to the output
#     directory and that is not known at configure time, so the value must be the
#     generator expression $<TARGET_FILE_DIR:...> — never a literal "Debug".
#   * The VARIABLE NAME is per-platform: PATH on Windows, LD_LIBRARY_PATH on Linux.
#     Linux already resolves the .so through the build-tree RPATH, so it is
#     belt-and-braces there — it is what would notice if RPATH were ever disabled.
#
# WHAT DEFEATS ALL OF THIS, and did (2026-08-13): a COPY of msgcore.dll or
# targetcore.dll left sitting in the test exes' own output directory. Windows
# searches the application directory BEFORE it looks at PATH, so such a copy wins
# over the entry prepended here and every test in the directory silently runs
# against it. Two stale copies were found next to the exes and deleted; while they
# were there a rebuilt library was NOT what ctest exercised, and a fix could be
# verified green without ever having been loaded. Nothing here puts them there —
# do not add a POST_BUILD copy step to "help". If a test needs a DLL, this loader
# path is the mechanism; a copy beside the exe is a stale result waiting to
# happen. check_repo_invariants.py fails the build if a POST_BUILD step appears.
#
# Call this ONCE, at the END of the including CMakeLists.txt: it reads the
# directory's accumulated TESTS property, so a new add_test() is covered
# automatically instead of failing the day somebody forgets the boilerplate.
# ---------------------------------------------------------------------------
function(_mscs_apply_loader_path)
    if(WIN32)
        set(_ldvar PATH)
    else()
        set(_ldvar LD_LIBRARY_PATH)
    endif()
    get_property(_tests DIRECTORY PROPERTY TESTS)
    if(_tests)
        set_tests_properties(${_tests} PROPERTIES ENVIRONMENT_MODIFICATION
            "${_ldvar}=path_list_prepend:$<TARGET_FILE_DIR:msgcore>;${_ldvar}=path_list_prepend:$<TARGET_FILE_DIR:targetcore>")
    endif()
endfunction()
