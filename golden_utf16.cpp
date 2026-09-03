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
// golden_utf16.cpp — UTF-16 pinning golden test (LinuxPortPlan.md §4.2 / LinuxPort_UTF16Audit.md)
//
// Builds a DETERMINISTIC IOMAGE-backed store with wide names + int cells, saves it
// to argv[1], reloads it, and verifies the values round-trip. Prints the on-disk
// image size. Because the wide layouts (VBLockName::aAlloc, VBLob::cBlob) are now
// 16-bit pinned, the same code + content must yield a BYTE-IDENTICAL .p2p on Windows
// and Linux — cross-check by diffing the two platforms' output files, or comparing
// the printed size + an external hash (sha256sum / certutil).
//
// Build (Linux):  g++ -std=c++23 -fpermissive -I../Msgcore -I../Msgcore/Platform \
//                     -I../Msgcore/Platform/win-compat golden_utf16.cpp \
//                     -L../Msgcore -lmsgcore -Wl,-rpath,../Msgcore -o golden_utf16

#include "stdafx.h"
#include "P2Pmsg.h"
#include "MsgVect.h"
#include "MsgDesc.h"
#include "Msgexception.h"
#include "P2PmsgMgr.h"
#include <cstdio>
#include <string>

// Astral (> U+FFFF) mixed with BMP: 'A', U+1F680 (🚀, needs a UTF-16 surrogate pair),
// U+20AC (€, BMP non-ASCII), 'B'. Written with a universal-character-name so the compiler
// encodes it as a surrogate PAIR on Windows' 16-bit wchar_t and a single 32-bit wchar_t on
// Linux — the very case the pinning helpers must convert. Round-tripping this proves astral
// support end-to-end (store -> save -> load -> c_wstr / c_name).
static const wchar_t kAstral[] = L"A\U0001F680\u20ACB";

static std::wstring widen(const char* p) {
    std::wstring w;
    if (p) for (; *p; ++p) w.push_back((wchar_t)(unsigned char)*p);
    return w;
}

static long file_size(const wchar_t* wpath) {
    std::string p;
    for (const wchar_t* q = wpath; *q; ++q) p.push_back((char)*q);   // ASCII paths in the test
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f) return -1;
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fclose(f);
    return n;
}

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <out.p2p>\n", argv[0]); return 2; }
    std::wstring wpath = widen(argv[1]);
    int rc = 0;
    bool astral_mem = false, astral_disk = false, astral_name = false;
    #define BC(m) do { std::fprintf(stderr, "[bc] %s\n", m); } while(0)
    try {
        // ---- build + save a deterministic store with WIDE names ----
        {
            BC("before mgr ctor");
            P2PmsgMgr  oMgr(VBLock_Addr64, 4096, 1u << 20);
            BC("after mgr ctor");
            P3PmsgVect oVect(4, L"Persisted", P3PmsgData((int)0));
            BC("after vect ctor");
            for (int i = 0; i < 4; i++)
                oVect.r_data(i).c_int((i + 1) * 100);
            BC("after vect fill");
            oMgr.r_Desc(P3PmsgField::AttrCMD_Create);
            BC("after r_Desc create");
            oMgr.r_Desc() += oVect;
            BC("after += vect");
            // A longer wide name to stress the inline-name storage (aAlloc / cBlob).
            // Must give the field an INT32 data cell up front (c_int() requires one).
            P3PmsgField oField(L"WideNameField_0123456789", P3PmsgData((int)0));
            oField.c_int(42);
            oMgr.r_Desc() += oField;
            BC("after += field");
            // Astral: a WSTR data cell (the FS-spike bug site) built from a surrogate-pair
            // string, and a field whose NAME contains the astral char (exercises c_name).
            P3PmsgData oAstralData = kAstral;                          // store -> c_wstr in memory
            astral_mem = (wcscmp(oAstralData.c_wstr(), kAstral) == 0);
            oMgr.r_Desc() += P3PmsgField(L"AstralData", oAstralData);
            oMgr.r_Desc() += P3PmsgField(kAstral, P3PmsgData((int)7)); // astral chars IN the name
            BC("after += astral");
            oMgr.Save(wpath.c_str());
            BC("after Save");
        }
        long nBytes = file_size(wpath.c_str());
        // ---- reload + verify the values survived serialisation ----
        {
            P2PmsgMgr  oMgr(wpath.c_str());
            P3PmsgVect oBack(oMgr.r_Desc().SelectVect(L"Persisted").r_Object());
            // Astral survives save/load: WSTR data cell value, and selection BY the astral name.
            LPCWSTR pAstral = oMgr.r_Desc().SelectItem(L"AstralData").c_wstr();
            astral_disk = (pAstral && wcscmp(pAstral, kAstral) == 0);
            astral_name = (oMgr.r_Desc().SelectItem(kAstral).c_int() == 7);
            bool ok = (int)oBack.GetCount() == 4
                   && oBack.r_data(0).c_int() == 100
                   && oBack.r_data(3).c_int() == 400
                   && oMgr.r_Desc().SelectItem(L"WideNameField_0123456789").c_int() == 42
                   && astral_mem && astral_disk && astral_name;
            std::printf("golden_utf16: image_size=%ld roundtrip=%s"
                        " (astral mem=%d disk=%d name=%d)\n",
                        nBytes, ok ? "PASS" : "FAIL",
                        (int)astral_mem, (int)astral_disk, (int)astral_name);
            if (!ok) rc = 1;
        }
    } catch (P2Pevent* pEVT) {
        std::string mod, msg;
        if (pEVT) {
            for (const wchar_t* w = pEVT->GetModule();  w && *w; ++w) mod.push_back((char)*w);
            for (const wchar_t* w = pEVT->GetMessage(); w && *w; ++w) msg.push_back((char)*w);
            pEVT->Cancel(false);
        }
        std::fprintf(stderr, "golden_utf16: unexpected P2Pevent  module=[%s]  message=[%s]\n",
                     mod.c_str(), msg.c_str());
        rc = 3;
    }
    return rc;
}
