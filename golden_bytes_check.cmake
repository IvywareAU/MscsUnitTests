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
# golden_bytes_check.cmake — cross-platform golden byte-identity gate (LinuxPortPlan §4.2).
#
# Regenerate the golden .p2p with golden_utf16 and compare it byte-for-byte against the
# checked-in reference. Replaces the Linux-only `bash -c "… && cmp …"` with a portable
# `cmake -E compare_files`, so a Windows-built and a Linux-built golden_utf16 both gate on
# producing the EXACT same serialised heap image (the cross-OS format guarantee).
#
# Driven via: ctest -> cmake -DGOLDEN_EXE=… -DOUT_IMG=… -DREF_IMG=… -P golden_bytes_check.cmake

if(NOT GOLDEN_EXE OR NOT OUT_IMG OR NOT REF_IMG)
    message(FATAL_ERROR "golden_bytes_check: GOLDEN_EXE / OUT_IMG / REF_IMG must all be set")
endif()

execute_process(COMMAND "${GOLDEN_EXE}" "${OUT_IMG}" RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "golden_utf16 failed to generate '${OUT_IMG}' (exit ${_rc})")
endif()

execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files "${OUT_IMG}" "${REF_IMG}"
                RESULT_VARIABLE _cmp)
if(NOT _cmp EQUAL 0)
    message(FATAL_ERROR
        "golden image '${OUT_IMG}' differs from reference '${REF_IMG}' "
        "-- serialised heap-format drift (§4.2)")
endif()

message(STATUS "golden_utf16_bytes: byte-identical to the reference image")
