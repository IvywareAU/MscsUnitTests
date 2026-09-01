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
// p2p_u8_smoke.cpp — smoke test for the TargetCore UTF-8 (_u8) C API surface
// (LinuxPortPlan.md §4.2, §6.2, Phase 6). The wchar_t p2p*_c entry points use each
// platform's native wide layout (UTF-16 on Windows, UTF-32 on Linux) and cannot
// carry a string portably through Panama/jextract; the _u8 twins take/return UTF-8
// and convert at the boundary. This proves the P2Paddr + P2PeerMsg _u8 twins are
// correctly wired (each delegates to its wchar_t base and converts BOTH directions),
// exercising multibyte UTF-8 (2-byte é / 3-byte € / 4-byte astral 🚀) — the msgcore
// counterpart of msgcore_u8_smoke, but for the transport-layer C API.
//
// Pure object-model: no sockets/io_uring, so it is deterministic + fast and gated.
// Verdict = exit code: 0 SUCCESS, non-zero on the first failed check.
//
// The returned const char* points at a thread-local buffer valid only until the next
// _u8 string-returning call on the same thread, so every getter result is compared
// immediately, before the following _u8 call.
//
// Build (Linux):
//   g++ -std=c++23 -I../TargetCore -I../Platform p2p_u8_smoke.cpp \
//       -L../build/TargetCore -ltargetcore -Wl,-rpath,../build/TargetCore -o p2p_u8_smoke

#include "TargetCore_c.h"
#include <cstdio>
#include <cstring>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s\n", msg); g_fail = 1; } \
    else std::printf("ok  : %s\n", msg); } while (0)

// Explicit UTF-8 bytes so the test is independent of the source-file encoding.
static const char* kAddr   = "Mesh.Caf\xC3\xA9";               // Mesh.café   (ASCII + 2-byte)
static const char* kLeaf   = "Caf\xC3\xA9";                    // café — p2paddr_c_name returns
                                                               // the node's own (leaf) name, not
                                                               // the full dotted path
static const char* kChild  = "Mesh.Caf\xC3\xA9.Leaf";          // a child of kAddr
static const char* kSrc    = "cli.no\xC3\xA9";                 // cli.noé
static const char* kDst    = "srv.\xE2\x82\xAC";               // srv.€        (3-byte)
static const char* kMsgID  = "Ping\xF0\x9F\x9A\x80";           // Ping🚀       (4-byte astral)

int main()
{
    std::printf("=== targetcore _u8 UTF-8 round-trip smoke ===\n");

    // ---- P2Paddr: UTF-8 in, UTF-8 out, byte-identical ----
    P2PAddrHandle hAddr = p2paddr_create_str_u8(kAddr);
    CHECK(hAddr != nullptr, "p2paddr_create_str_u8 (multibyte addr)");
    if (hAddr)
    {
        const char* gotAddr = p2paddr_c_name_u8(hAddr);       // leaf name, multibyte preserved
        CHECK(gotAddr && std::strcmp(gotAddr, kLeaf) == 0, "p2paddr_c_name_u8 byte-identical (leaf)");
        if (gotAddr) std::printf("       leaf = \"%s\" (%zu bytes)\n", gotAddr, std::strlen(gotAddr));

        // Predicates just need to accept the UTF-8 arg and return a valid bool (0/1);
        // the hierarchy relationship is asserted to prove the arg reached the base call.
        int isChild = p2paddr_is_child_u8(hAddr, kChild);
        CHECK(isChild == 0 || isChild == 1, "p2paddr_is_child_u8 returns bool");
        std::printf("       is_child(\"...Leaf\") = %d\n", isChild);

        int isRable = p2paddr_is_rable_u8(hAddr, kChild);
        CHECK(isRable == 0 || isRable == 1, "p2paddr_is_rable_u8 returns bool");
        std::printf("       is_rable(\"...Leaf\") = %d\n", isRable);

        p2paddr_destroy(hAddr);
    }

    // ---- P2PeerMsg: source / destin / name round-trip through _u8 ----
    P2PeerMsgHandle hMsg = p2peermsg_create_full_u8(kSrc, kDst, kMsgID, nullptr, 0);
    CHECK(hMsg != nullptr, "p2peermsg_create_full_u8 (é src / € dst / astral msgID)");
    if (hMsg)
    {
        const char* gotSrc = p2peermsg_get_source_u8(hMsg);
        CHECK(gotSrc && std::strcmp(gotSrc, kSrc) == 0, "p2peermsg_get_source_u8 byte-identical");
        const char* gotDst = p2peermsg_get_destin_u8(hMsg);
        CHECK(gotDst && std::strcmp(gotDst, kDst) == 0, "p2peermsg_get_destin_u8 byte-identical (€)");
        const char* gotName = p2peermsg_c_name_u8(hMsg);
        CHECK(gotName && std::strcmp(gotName, kMsgID) == 0, "p2peermsg_c_name_u8 byte-identical (astral)");
        if (gotName) std::printf("       name = \"%s\" (%zu bytes)\n", gotName, std::strlen(gotName));

        // setter twin: reassign source via _u8 and read it back
        p2peermsg_set_source_u8(hMsg, kDst);
        const char* gotSrc2 = p2peermsg_get_source_u8(hMsg);
        CHECK(gotSrc2 && std::strcmp(gotSrc2, kDst) == 0, "p2peermsg_set_source_u8 round-trip (€)");

        p2peermsg_destroy(hMsg);
    }

    // ---- create_msgid twin ----
    P2PeerMsgHandle hMsg2 = p2peermsg_create_msgid_u8(kMsgID);
    CHECK(hMsg2 != nullptr, "p2peermsg_create_msgid_u8");
    if (hMsg2)
    {
        const char* gotName2 = p2peermsg_c_name_u8(hMsg2);
        CHECK(gotName2 && std::strcmp(gotName2, kMsgID) == 0, "create_msgid_u8 -> c_name_u8 (astral)");
        p2peermsg_destroy(hMsg2);
    }

    std::printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: SUCCESS\n");
    return g_fail;
}
