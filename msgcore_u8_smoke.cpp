// Copyright © 2026 Khrustal & Mann
//              MELBOURNE, VICTORIA, AUSTRALIA, 3000
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.
//
// msgcore_u8_smoke.cpp — smoke test for the UTF-8 (_u8) C API surface
// (LinuxPortPlan.md §6, Phase 6). Proves that a UTF-8 string round-trips
// name+value through the store identically on BOTH platforms, exercising 1/2/3/4
// -byte UTF-8 (ASCII, U+00E9 é, U+20AC €, U+1F680 🚀 astral) — which is the whole
// point of the _u8 layer, since the wchar_t entry points use UTF-16 on Windows
// and UTF-32 on Linux and cannot carry a string portably.
//
// Verdict = exit code: 0 SUCCESS, non-zero on the first failed check.
//
// Build (Linux):
//   g++ -std=c++23 -I../Msgcore msgcore_u8_smoke.cpp \
//       -L../build/Msgcore -lmsgcore -Wl,-rpath,../build/Msgcore -o msgcore_u8_smoke

#include "Msgcore_c.h"
#include <cstdio>
#include <cstring>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s\n", msg); g_fail = 1; } \
    else std::printf("ok  : %s\n", msg); } while (0)

// Explicit UTF-8 bytes so the test is independent of the source-file encoding.
static const char* kName = "caf\xC3\xA9";                       // café  (ASCII + 2-byte)
static const char* kVal  = "Hi \xF0\x9F\x9A\x80 caf\xC3\xA9 \xE2\x82\xAC!"; // 4/2/3-byte

int main()
{
    std::printf("=== msgcore _u8 UTF-8 round-trip smoke ===\n");

    MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
    CHECK(hMgr != nullptr, "mgr_create");
    if (!hMgr) return 2;

    // ---- write via _u8 on the LIVE root ----
    MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
    CHECK(hRoot != nullptr, "mgr_root");
    MsgFieldHandle hDecl = msgcore_field_declare_wstr_u8(hRoot, kName, kVal, 1);
    CHECK(hDecl != nullptr, "declare_wstr_u8 (astral name+value)");
    if (hDecl) msgcore_field_destroy(hDecl);

    // ---- read back via _u8 ----
    CHECK(msgcore_field_exists_u8(hRoot, kName) == 1, "exists_u8");

    MsgFieldHandle hChild = msgcore_field_child_u8(hRoot, kName);
    CHECK(hChild != nullptr, "field_child_u8");
    if (hChild)
    {
        const char* gotName = msgcore_field_get_name_u8(hChild);
        CHECK(gotName && std::strcmp(gotName, kName) == 0, "get_name_u8 byte-identical");
        if (gotName) std::printf("       name = \"%s\" (%zu bytes)\n", gotName, std::strlen(gotName));

        const char* gotVal = msgcore_field_get_wstr_u8(hChild);
        CHECK(gotVal && std::strcmp(gotVal, kVal) == 0, "get_wstr_u8 byte-identical (incl astral)");
        if (gotVal) std::printf("       val  = \"%s\" (%zu bytes)\n", gotVal, std::strlen(gotVal));

        msgcore_field_destroy(hChild);
    }

    // ---- wildcard match through _u8 ----
    CHECK(msgcore_wildcard_match_u8("caf*", kName) == 1, "wildcard_match_u8");

    msgcore_field_destroy(hRoot);
    msgcore_mgr_destroy(hMgr);

    std::printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: SUCCESS\n");
    return g_fail;
}
