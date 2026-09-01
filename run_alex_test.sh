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
# run_alex_test.sh — orchestrate the two-process AlexTest (LinuxPortPlan Phase-3 exit).
#
# Launches the server, then the client, and asserts BOTH processes exit 0.
# The server's exit 0 is the authoritative proof that the client's BCast
# crossed the process boundary over io_uring TCP.
#
# Usage: run_alex_test.sh [/path/to/alex_test] [port]
set -u

EXE="${1:-./alex_test}"
PORT="${2:-7811}"

echo "=== two-process AlexTest: $EXE on 127.0.0.1:$PORT ==="

# Start the server; it self-terminates on BCast receipt or after a 15s timeout.
"$EXE" server "$PORT" > /tmp/alex_server.log 2>&1 &
SRV_PID=$!
echo "server launched (pid=$SRV_PID); waiting for bind/listen..."
sleep 1.5

# Run the client to completion.
"$EXE" send 127.0.0.1 "$PORT" > /tmp/alex_client.log 2>&1
CLI_RC=$?
echo "client exit=$CLI_RC"

# Reap the server (it should exit on its own once it got the BCast).
wait "$SRV_PID"
SRV_RC=$?
echo "server exit=$SRV_RC"

echo "----- server log -----"; cat /tmp/alex_server.log
echo "----- client log -----"; cat /tmp/alex_client.log
echo "----------------------"

if [ "$SRV_RC" -eq 0 ] && [ "$CLI_RC" -eq 0 ]; then
    echo "RESULT: PASS (server received the client's BCast; both processes exit 0)"
    exit 0
else
    echo "RESULT: FAIL (server_rc=$SRV_RC client_rc=$CLI_RC)"
    exit 1
fi
