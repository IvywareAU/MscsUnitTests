#!/usr/bin/env bash
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
# run_sanitizers.sh — build the Linux port under a sanitizer and run the teardown stress
# (LinuxPortPlan §5.6 cancel_fd teardown, §8 "kill mid-flight x 10^3 under ASan", Risk #2
# SINGLE_ISSUER cross-thread io_uring submission races, Risk #3 teardown refcount UAF/leaks).
#
# For each sanitizer it configures a dedicated build dir with the -fsanitize flag applied
# GLOBALLY (so libmsgcore.so + libtargetcore.so + p2piocp.cpp + the harness are all
# instrumented — required for TSan to see across the .so boundary and for ASan to catch
# UAF/leaks inside the libraries), builds teardown_stress (which pulls both libs), and runs
# it. A sanitizer report aborts the process non-zero, which fails the run.
#
# Usage:  run_sanitizers.sh [address|thread ...]      (default: both)
#   env:  CONNS=1000 CONC=8 DELAY=12  (override the stress dimensions)
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"     # MSCS root (e.g. ~/portci)
CONNS="${CONNS:-1000}"; CONC="${CONC:-8}"; DELAY="${DELAY:-12}"

run_one() {
    local san="$1"
    local dir="$ROOT/build-$san"
    echo "================ $san : configure ($dir) ================"
    cmake -S "$ROOT" -B "$dir" -G Ninja -DMSCS_BUILD_LIBS=ON \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_CXX_FLAGS="-fsanitize=$san -g -O1 -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=$san" \
        -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=$san" >/dev/null || return 2

    echo "================ $san : build teardown_stress ================"
    cmake --build "$dir" --target teardown_stress 2>&1 | tail -4 || return 2

    echo "================ $san : run ($CONNS conns, conc $CONC, delay $DELAY) ================"
    local rc
    if [ "$san" = address ]; then
        ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:abort_on_error=1" \
            "$dir/MscsUnitTests/teardown_stress" "$CONNS" "$CONC" "$DELAY"
        rc=$?
    else
        TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1" \
            "$dir/MscsUnitTests/teardown_stress" "$CONNS" "$CONC" "$DELAY"
        rc=$?
    fi
    echo "================ $san : exit=$rc ================"
    return $rc
}

SANS="${*:-address thread}"
overall=0
for s in $SANS; do
    run_one "$s" || overall=1
done
if [ "$overall" -eq 0 ]; then
    echo "ALL SANITIZERS CLEAN"
else
    echo "SANITIZER FAILURE (see above)"
fi
exit "$overall"
