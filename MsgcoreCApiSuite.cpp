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
// MsgcoreCApiSuite.cpp
//
// Unit tests for the flat C wrapper (Msgcore_c.h) that the P2P FileSystem
// TreeFS core will call. This is the first test coverage of the C API itself
// (the other suites exercise the C++ classes directly).
//
// The load-bearing question for the whole filesystem plan (p2p_FileSystem.md)
// is: do tree mutations performed through C-API handles actually persist into
// the live P2PmsgMgr tree, survive a Save/Load, and remain addressable by a
// stable positional handle (the FS inode)?
//
// The answer, established here, is nuanced and important for the FS design:
//   * msgcore_mgr_as_field / msgcore_*_select_item return a DETACHED deep copy
//     (safe to read; mutations are lost).
//   * msgcore_mgr_root / msgcore_field_child return a LIVE alias of the heap
//     node; declares / renames / retypes through those DO persist.
// These cases pin that contract and cover the new FS-support wrappers:
//   msgcore_field_get_p2pos / msgcore_mgr_p2pos2field / msgcore_mgr_p2pos2path,
//   msgcore_type_name, msgcore_field_rename_child / _move_child / _retype_child_*.

#include "stdafx.h"

#include "Msgcore_c.h"

#include "TestFramework.h"

#include <cwchar>
#include <cstring>

// ---------------------------------------------------------------------------
static void MakeTempP2pPath(wchar_t* szOut, const wchar_t* lpszLeaf)
{
    wchar_t szDir[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, szDir);
    swprintf_s(szOut, MAX_PATH, L"%s%s", szDir, lpszLeaf);
}

// ---------------------------------------------------------------------------
// msgcore_type_name : pure MSGCORE_DATA_* -> stable ASCII name (the ".type" file)
// ---------------------------------------------------------------------------
static void Test_CApi_TypeNames()
{
    TF_CASE("msgcore_type_name maps the documented type codes")
    {
        TF_CHECK(strcmp(msgcore_type_name(MSGCORE_DATA_INT32),  "INT32")  == 0);
        TF_CHECK(strcmp(msgcore_type_name(MSGCORE_DATA_INT64),  "INT64")  == 0);
        TF_CHECK(strcmp(msgcore_type_name(MSGCORE_DATA_DOUBLE), "DOUBLE") == 0);
        TF_CHECK(strcmp(msgcore_type_name(MSGCORE_DATA_BOOL),   "BOOL")   == 0);
        TF_CHECK(strcmp(msgcore_type_name(MSGCORE_DATA_WSTR16), "WSTR16") == 0);
        TF_CHECK(strcmp(msgcore_type_name(MSGCORE_DATA_BLOB16), "BLOB16") == 0);
        TF_CHECK(strcmp(msgcore_type_name(MSGCORE_DATA_GUID),   "GUID")   == 0);
    }
    TF_CASE("msgcore_type_name never returns NULL for unknown codes")
    {
        const char* p = msgcore_type_name(200);
        TF_CHECK(p != nullptr);
        TF_CHECK(p != nullptr && strcmp(p, "UNKNOWN") == 0);
    }
}

// ---------------------------------------------------------------------------
// Detached-vs-live contract: mutating through msgcore_mgr_as_field must NOT be
// visible in the live tree; mutating through msgcore_mgr_root MUST be.
// ---------------------------------------------------------------------------
static void Test_CApi_LiveVsDetached()
{
    TF_CASE("declares through msgcore_mgr_as_field do NOT reach the live tree")
    {
        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
        MsgFieldHandle hDetached = msgcore_mgr_as_field(hMgr);
        TF_CHECK(hDetached != nullptr);
        if (hDetached)
        {
            // declare returns an OWNED field handle (a new P3PmsgField) — dispose it,
            // else it leaks (LeakSanitizer, MsgcoreCApiSuite.cpp:73).
            MsgFieldHandle hDecl = msgcore_field_declare_wstr(hDetached, L"Ghost", L"x", 1);
            msgcore_field_destroy(hDecl);
        }
        msgcore_field_destroy(hDetached);

        MsgFieldHandle hLive = msgcore_mgr_root(hMgr);
        TF_CHECK(hLive != nullptr);
        TF_CHECK(hLive && msgcore_field_exists(hLive, L"Ghost") == 0);   // lost, as expected
        msgcore_field_destroy(hLive);
        msgcore_mgr_destroy(hMgr);
    }

    TF_CASE("declares through msgcore_mgr_root are visible via a fresh live handle")
    {
        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
        {
            MsgFieldHandle hLive = msgcore_mgr_root(hMgr);
            TF_CHECK(hLive != nullptr);
            if (hLive)
            {
                // declare returns an OWNED field handle — dispose it (else leaks).
                MsgFieldHandle hDecl = msgcore_field_declare_wstr(hLive, L"Real", L"x", 1);
                msgcore_field_destroy(hDecl);
            }
            msgcore_field_destroy(hLive);
        }
        {
            MsgFieldHandle hLive = msgcore_mgr_root(hMgr);
            TF_CHECK(hLive && msgcore_field_exists(hLive, L"Real") == 1);
            msgcore_field_destroy(hLive);
        }
        msgcore_mgr_destroy(hMgr);
    }
}

// ---------------------------------------------------------------------------
// The core question: build via the C API, Save, Load, read back.
// ---------------------------------------------------------------------------
static void Test_CApi_PersistThroughSaveLoad()
{
    TF_CASE("declares through a live handle persist across mgr Save/Load")
    {
        wchar_t szPath[MAX_PATH] = { 0 };
        MakeTempP2pPath(szPath, L"mscs_capi_persist.p2p");

        // --- write phase ---
        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
        TF_CHECK(hMgr != nullptr);
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            TF_CHECK(hRoot != nullptr);
            if (hRoot)
            {
                MsgFieldHandle hDecl = msgcore_field_declare_wstr(hRoot, L"Topic", L"Hello", 1);
                TF_CHECK(hDecl != nullptr);
                msgcore_field_destroy(hDecl);
            }
            msgcore_field_destroy(hRoot);
        }
        int saved = msgcore_mgr_save(hMgr, szPath);
        TF_CHECK_EQ(saved, 1);
        msgcore_mgr_destroy(hMgr);

        // --- read phase ---
        MsgMgrHandle hMgr2 = msgcore_mgr_open_file(szPath);
        TF_CHECK(hMgr2 != nullptr);
        if (hMgr2)
        {
            MsgFieldHandle hRoot2 = msgcore_mgr_root(hMgr2);
            TF_CHECK(hRoot2 && msgcore_field_exists(hRoot2, L"Topic") == 1);

            MsgFieldHandle hTopic = msgcore_field_child(hRoot2, L"Topic");
            TF_CHECK(hTopic != nullptr);
            const wchar_t* val = hTopic ? msgcore_field_get_wstr(hTopic) : nullptr;
            TF_CHECK(val != nullptr && wcscmp(val, L"Hello") == 0);

            msgcore_field_destroy(hTopic);
            msgcore_field_destroy(hRoot2);
            msgcore_mgr_destroy(hMgr2);
        }
        _wremove(szPath);
    }
}

// ---------------------------------------------------------------------------
// P2Pos is the FS inode: get it from a live node, resolve it back to node+path.
// ---------------------------------------------------------------------------
static void Test_CApi_P2PosRoundTrip()
{
    TF_CASE("get_p2pos round-trips through p2pos2field / p2pos2path")
    {
        wchar_t szPath[MAX_PATH] = { 0 };
        MakeTempP2pPath(szPath, L"mscs_capi_p2pos.p2p");

        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            if (hRoot)
            {
                MsgFieldHandle hDecl = msgcore_field_declare_wstr(hRoot, L"Node", L"v", 1);
                msgcore_field_destroy(hDecl);
            }
            msgcore_field_destroy(hRoot);
        }
        msgcore_mgr_save(hMgr, szPath);
        msgcore_mgr_destroy(hMgr);

        MsgMgrHandle hMgr2 = msgcore_mgr_open_file(szPath);
        TF_CHECK(hMgr2 != nullptr);
        if (hMgr2)
        {
            MsgFieldHandle hRoot2 = msgcore_mgr_root(hMgr2);
            MsgFieldHandle hNode  = hRoot2 ? msgcore_field_child(hRoot2, L"Node") : nullptr;
            TF_CHECK(hNode != nullptr);

            if (hNode)
            {
                unsigned long long pos = msgcore_field_get_p2pos(hNode);
                TF_CHECK(pos != 0ULL);

                MsgFieldHandle hByPos = msgcore_mgr_p2pos2field(hMgr2, pos);
                TF_CHECK(hByPos != nullptr);
                const wchar_t* nm = hByPos ? msgcore_field_get_name(hByPos) : nullptr;
                TF_CHECK(nm != nullptr && wcscmp(nm, L"Node") == 0);

                const wchar_t* path = msgcore_mgr_p2pos2path(hMgr2, pos);
                TF_CHECK(path != nullptr);

                msgcore_field_destroy(hByPos);
            }
            msgcore_field_destroy(hNode);
            msgcore_field_destroy(hRoot2);
            msgcore_mgr_destroy(hMgr2);
        }
        _wremove(szPath);
    }
}

// ---------------------------------------------------------------------------
// st_mtime: set_tstamp / get_tstamp. Also pins the P3Pmsg_GetTStamp fix (the
// getter previously read the wrong attribute key and always returned 0).
// Handles are re-resolved per op (VBHeap-relocation discipline, §4.4).
// ---------------------------------------------------------------------------
static void Test_CApi_Tstamp()
{
    TF_CASE("set_tstamp is read back by get_tstamp (getter-key fix)")
    {
        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            if (hRoot)
            {
                MsgFieldHandle h = msgcore_field_declare_wstr(hRoot, L"Node", L"v", 1);
                msgcore_field_destroy(h);
            }
            msgcore_field_destroy(hRoot);
        }

        const long long kTs = 1234567890LL;
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            MsgFieldHandle hNode = hRoot ? msgcore_field_child(hRoot, L"Node") : nullptr;
            TF_CHECK(hNode != nullptr);
            if (hNode)
            {
                long long stored = msgcore_field_set_tstamp(hNode, kTs);
                TF_CHECK_EQ(stored, kTs);
            }
            msgcore_field_destroy(hNode);
            msgcore_field_destroy(hRoot);
        }

        // fresh live handle: the fixed getter must now return the stored value
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            MsgFieldHandle hNode = hRoot ? msgcore_field_child(hRoot, L"Node") : nullptr;
            TF_CHECK(hNode && msgcore_field_get_tstamp(hNode) == kTs);
            msgcore_field_destroy(hNode);
            msgcore_field_destroy(hRoot);
        }

        // an unstamped node reads 0
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            if (hRoot)
            {
                MsgFieldHandle h = msgcore_field_declare_wstr(hRoot, L"Bare", L"", 1);
                msgcore_field_destroy(h);
            }
            MsgFieldHandle hBare = hRoot ? msgcore_field_child(hRoot, L"Bare") : nullptr;
            TF_CHECK(hBare && msgcore_field_get_tstamp(hBare) == 0LL);
            msgcore_field_destroy(hBare);
            msgcore_field_destroy(hRoot);
        }

        msgcore_mgr_destroy(hMgr);
    }

    TF_CASE("set_tstamp(-1) records 'now' and it reads back identically")
    {
        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            if (hRoot)
            {
                MsgFieldHandle h = msgcore_field_declare_wstr(hRoot, L"Node", L"v", 1);
                msgcore_field_destroy(h);
            }
            msgcore_field_destroy(hRoot);
        }

        long long now = 0;
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            MsgFieldHandle hNode = hRoot ? msgcore_field_child(hRoot, L"Node") : nullptr;
            if (hNode)
                now = msgcore_field_set_tstamp(hNode, -1);
            TF_CHECK(now > 0);
            msgcore_field_destroy(hNode);
            msgcore_field_destroy(hRoot);
        }
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            MsgFieldHandle hNode = hRoot ? msgcore_field_child(hRoot, L"Node") : nullptr;
            TF_CHECK(hNode && msgcore_field_get_tstamp(hNode) == now);
            msgcore_field_destroy(hNode);
            msgcore_field_destroy(hRoot);
        }
        msgcore_mgr_destroy(hMgr);
    }

    TF_CASE("a timestamp persists across mgr Save/Load")
    {
        wchar_t szPath[MAX_PATH] = { 0 };
        MakeTempP2pPath(szPath, L"mscs_capi_tstamp.p2p");
        const long long kTs = 1700000000LL;

        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            if (hRoot)
            {
                MsgFieldHandle h = msgcore_field_declare_wstr(hRoot, L"Node", L"v", 1);
                msgcore_field_destroy(h);
            }
            msgcore_field_destroy(hRoot);
        }
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            MsgFieldHandle hNode = hRoot ? msgcore_field_child(hRoot, L"Node") : nullptr;
            if (hNode) msgcore_field_set_tstamp(hNode, kTs);
            msgcore_field_destroy(hNode);
            msgcore_field_destroy(hRoot);
        }
        msgcore_mgr_save(hMgr, szPath);
        msgcore_mgr_destroy(hMgr);

        MsgMgrHandle hMgr2 = msgcore_mgr_open_file(szPath);
        TF_CHECK(hMgr2 != nullptr);
        if (hMgr2)
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr2);
            MsgFieldHandle hNode = hRoot ? msgcore_field_child(hRoot, L"Node") : nullptr;
            TF_CHECK(hNode && msgcore_field_get_tstamp(hNode) == kTs);
            msgcore_field_destroy(hNode);
            msgcore_field_destroy(hRoot);
            msgcore_mgr_destroy(hMgr2);
        }
        _wremove(szPath);
    }
}

// ---------------------------------------------------------------------------
// rename(2) within a directory.
// ---------------------------------------------------------------------------
static void Test_CApi_RenameChild()
{
    TF_CASE("rename_child renames a descendant in the live tree")
    {
        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            if (hRoot)
            {
                MsgFieldHandle h = msgcore_field_declare_wstr(hRoot, L"A", L"x", 1);
                msgcore_field_destroy(h);
            }
            msgcore_field_destroy(hRoot);
        }

        int rc = 0;
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            rc = msgcore_field_rename_child(hRoot, L"A", L"A2");
            msgcore_field_destroy(hRoot);
        }
        TF_CHECK_EQ(rc, 1);

        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            TF_CHECK(hRoot && msgcore_field_exists(hRoot, L"A2") == 1);
            TF_CHECK(hRoot && msgcore_field_exists(hRoot, L"A")  == 0);
            msgcore_field_destroy(hRoot);
        }

        int rcMissing = 1;
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            rcMissing = msgcore_field_rename_child(hRoot, L"Nope", L"Whatever");
            msgcore_field_destroy(hRoot);
        }
        TF_CHECK_EQ(rcMissing, 0);

        msgcore_mgr_destroy(hMgr);
    }
}

// ---------------------------------------------------------------------------
// rename(2) across directories.
// ---------------------------------------------------------------------------
static void Test_CApi_MoveChild()
{
    TF_CASE("move_child relocates a descendant between parents in the live tree")
    {
        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            if (hRoot)
            {
                MsgFieldHandle h1 = msgcore_field_declare_wstr(hRoot, L"Dir",  L"", 1);
                MsgFieldHandle h2 = msgcore_field_declare_wstr(hRoot, L"Leaf", L"data", 1);
                msgcore_field_destroy(h1);
                msgcore_field_destroy(h2);
            }
            msgcore_field_destroy(hRoot);
        }

        int rc = 0;
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            MsgFieldHandle hDir  = hRoot ? msgcore_field_child(hRoot, L"Dir") : nullptr;
            TF_CHECK(hDir != nullptr);
            if (hRoot && hDir)
                rc = msgcore_field_move_child(hRoot, hDir, L"Leaf");
            msgcore_field_destroy(hDir);
            msgcore_field_destroy(hRoot);
        }
        TF_CHECK_EQ(rc, 1);

        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            TF_CHECK(hRoot && msgcore_field_exists(hRoot, L"Leaf") == 0);
            MsgFieldHandle hDir = hRoot ? msgcore_field_child(hRoot, L"Dir") : nullptr;
            TF_CHECK(hDir != nullptr);
            TF_CHECK(hDir && msgcore_field_exists(hDir, L"Leaf") == 1);
            msgcore_field_destroy(hDir);
            msgcore_field_destroy(hRoot);
        }

        msgcore_mgr_destroy(hMgr);
    }
}

// ---------------------------------------------------------------------------
// The ".type" write path.
// ---------------------------------------------------------------------------
static void Test_CApi_RetypeChild()
{
    TF_CASE("retype_child changes a child's data type in place")
    {
        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            if (hRoot)
            {
                MsgFieldHandle h = msgcore_field_declare_int(hRoot, L"Num", 42, 1);
                msgcore_field_destroy(h);
            }
            msgcore_field_destroy(hRoot);
        }

        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            MsgFieldHandle hNum  = hRoot ? msgcore_field_child(hRoot, L"Num") : nullptr;
            TF_CHECK(hNum && msgcore_field_get_data_type(hNum) != MSGCORE_DATA_WSTR16);
            msgcore_field_destroy(hNum);
            msgcore_field_destroy(hRoot);
        }

        int rc = 0;
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            rc = msgcore_field_retype_child_wstr(hRoot, L"Num", L"hello");
            msgcore_field_destroy(hRoot);
        }
        TF_CHECK_EQ(rc, 1);

        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            MsgFieldHandle hNum  = hRoot ? msgcore_field_child(hRoot, L"Num") : nullptr;
            TF_CHECK(hNum && msgcore_field_get_data_type(hNum) == MSGCORE_DATA_WSTR16);
            msgcore_field_destroy(hNum);
            msgcore_field_destroy(hRoot);
        }

        int rcMissing = 1;
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            rcMissing = msgcore_field_retype_child_int(hRoot, L"Ghost", 1);
            msgcore_field_destroy(hRoot);
        }
        TF_CHECK_EQ(rcMissing, 0);

        msgcore_mgr_destroy(hMgr);
    }
}

// ---------------------------------------------------------------------------
// msgcore_type_from_name: inverse of msgcore_type_name (the ".type" write path).
// ---------------------------------------------------------------------------
static void Test_CApi_TypeFromName()
{
    TF_CASE("type_from_name inverts type_name for every code, 0xFF for unknown")
    {
        const unsigned char kCodes[] = {
            MSGCORE_DATA_NULL,  MSGCORE_DATA_INT08,  MSGCORE_DATA_UINT08,
            MSGCORE_DATA_INT16, MSGCORE_DATA_UINT16, MSGCORE_DATA_INT32,
            MSGCORE_DATA_UINT32, MSGCORE_DATA_INT64, MSGCORE_DATA_UINT64,
            MSGCORE_DATA_FLOAT, MSGCORE_DATA_DOUBLE, MSGCORE_DATA_BOOL,
            MSGCORE_DATA_BSTR16, MSGCORE_DATA_WSTR16, MSGCORE_DATA_BLOB16,
            MSGCORE_DATA_GUID,
        };
        for (unsigned char code : kCodes)
            TF_CHECK_EQ((int)msgcore_type_from_name(msgcore_type_name(code)), (int)code);

        TF_CHECK_EQ((int)msgcore_type_from_name("UNKNOWN"), 0xFF);
        TF_CHECK_EQ((int)msgcore_type_from_name("int32"),   0xFF);   // case-sensitive
        TF_CHECK_EQ((int)msgcore_type_from_name(""),        0xFF);
        TF_CHECK_EQ((int)msgcore_type_from_name(nullptr),   0xFF);
    }
}

// ---------------------------------------------------------------------------
// Headless trigger sink: a windowless host gets a function-pointer callback for
// armed nodes, in place of the HWND PostMessage.
// ---------------------------------------------------------------------------
namespace {
struct TrigCapture { int count; unsigned int lastType; unsigned long long lastPos; };
static void TrigSink(void* pUser, unsigned int nType, unsigned long long p2pos)
{
    TrigCapture* c = static_cast<TrigCapture*>(pUser);
    c->count++;
    c->lastType = nType;
    c->lastPos  = p2pos;
}
} // namespace

static void Test_CApi_TriggerSink()
{
    TF_CASE("an armed node fires the headless sink on manual fire; drop stops it")
    {
        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);

        unsigned long long pos = 0;
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            MsgFieldHandle h = msgcore_field_declare_wstr(hRoot, L"Watched", L"v", 1);
            MsgFieldHandle live = msgcore_field_child(hRoot, L"Watched");
            pos = msgcore_field_get_p2pos(live);
            msgcore_field_destroy(live);
            msgcore_field_destroy(h);
            msgcore_field_destroy(hRoot);
        }
        TF_CHECK(pos != 0);

        TrigCapture cap = { 0, 0, 0 };
        msgcore_mgr_set_trigger_sink(hMgr, &TrigSink, &cap);
        msgcore_mgr_create_trigger(hMgr, MSGCORE_TRIGGER_UPDATE | MSGCORE_TRIGGER_INSERT, pos);

        // Fire UPDATE -> sink called once with (UPDATE, pos). (Avoid firing the
        // DELETE mask as a probe: ProcTriggers treats a DELETE pass as "object
        // gone" and drops ALL of the node's registrations.)
        TF_CHECK_EQ(msgcore_mgr_fire_trigger(hMgr, MSGCORE_TRIGGER_UPDATE, pos), 1);
        TF_CHECK_EQ(cap.count, 1);
        TF_CHECK_EQ((int)cap.lastType, MSGCORE_TRIGGER_UPDATE);
        TF_CHECK(cap.lastPos == pos);

        // The INSERT arm is independent and fires on its own mask.
        TF_CHECK_EQ(msgcore_mgr_fire_trigger(hMgr, MSGCORE_TRIGGER_INSERT, pos), 1);
        TF_CHECK_EQ(cap.count, 2);
        TF_CHECK_EQ((int)cap.lastType, MSGCORE_TRIGGER_INSERT);

        // Drop the UPDATE arm -> no more UPDATE callbacks; INSERT still armed.
        msgcore_mgr_drop_triggers(hMgr, MSGCORE_TRIGGER_UPDATE, pos);
        TF_CHECK_EQ(msgcore_mgr_fire_trigger(hMgr, MSGCORE_TRIGGER_UPDATE, pos), 0);
        TF_CHECK_EQ(cap.count, 2);

        // Clearing the sink is safe even while the INSERT registration remains.
        msgcore_mgr_set_trigger_sink(hMgr, nullptr, nullptr);
        TF_CHECK_EQ(msgcore_mgr_fire_trigger(hMgr, MSGCORE_TRIGGER_INSERT, pos), 1);
        TF_CHECK_EQ(cap.count, 2);   // sink cleared -> capture unchanged

        msgcore_mgr_destroy(hMgr);
    }

    TF_CASE("deleting an armed node auto-fires the sink with DELETE")
    {
        MsgMgrHandle hMgr = msgcore_mgr_create_nn(MSGCORE_ADDR_64, 4096, 1u << 20);

        unsigned long long pos = 0;
        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            MsgFieldHandle h = msgcore_field_declare_wstr(hRoot, L"Doomed", L"v", 1);
            MsgFieldHandle live = msgcore_field_child(hRoot, L"Doomed");
            pos = msgcore_field_get_p2pos(live);
            msgcore_field_destroy(live);
            msgcore_field_destroy(h);
            msgcore_field_destroy(hRoot);
        }

        TrigCapture cap = { 0, 0, 0 };
        msgcore_mgr_set_trigger_sink(hMgr, &TrigSink, &cap);
        msgcore_mgr_create_trigger(hMgr, MSGCORE_TRIGGER_DELETE, pos);

        {
            MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
            (void)msgcore_field_delete_item(hRoot, L"Doomed");
            msgcore_field_destroy(hRoot);
        }
        TF_CHECK_EQ(cap.count, 1);
        TF_CHECK_EQ((int)cap.lastType, MSGCORE_TRIGGER_DELETE);
        TF_CHECK(cap.lastPos == pos);

        msgcore_mgr_destroy(hMgr);
    }
}

// ---------------------------------------------------------------------------
// Handle validation across the flat C ABI (SECURITY_REVIEW M1)
//
// Every handle typedef in Msgcore_c.h is `void*`, and until the registry landed
// each entry point static_cast<>ed whatever arrived straight to its C++ class.
// Three things were therefore indistinguishable from a valid handle: a pointer
// this API never issued, one it issued and has since destroyed, and one of a
// DIFFERENT kind (nine unrelated classes, one ABI).
//
// These cases drive the C surface the way a hostile or merely buggy FFI caller
// would. The bogus-pointer case uses (void*)0x1 deliberately: any design that
// validates by reading a magic word THROUGH the caller's pointer faults there,
// which is why the registry never dereferences what it is handed.
//
// The last case is the control. Without it every case here would still pass
// against an API that answered "invalid" to everything.
// ---------------------------------------------------------------------------
static void Test_CApi_HandleGuards()
{
    TF_CASE("a pointer the C API never issued is refused, not dereferenced")
    {
        void* pvBogus = (void*)0x1;         // faults on any read-through check

        TF_CHECK_EQ(msgcore_mgr_is_dirty(pvBogus), 0);
        TF_CHECK(msgcore_mgr_get_filename(pvBogus) == nullptr);
        TF_CHECK(msgcore_mgr_root(pvBogus)         == nullptr);
        TF_CHECK(msgcore_field_child(pvBogus, L"x") == nullptr);
        TF_CHECK_EQ(msgcore_field_exists(pvBogus, L"x"), 0);
        TF_CHECK(msgcore_curs_get_field(pvBogus)   == nullptr);
        TF_CHECK_EQ(msgcore_list_get_count(pvBogus), 0);
        TF_CHECK_EQ(msgcore_vect_get_count(pvBogus), 0);

        //  Destroy must also refuse it rather than delete it.
        msgcore_field_destroy(pvBogus);
        msgcore_mgr_destroy(pvBogus);
    }

    TF_CASE("a destroyed handle is refused, and a second destroy is a no-op")
    {
        MsgMgrHandle hMgr = msgcore_mgr_create();
        TF_CHECK(hMgr != nullptr);

        MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
        TF_CHECK(hRoot != nullptr);
        //  declare_int hands back an OWNING handle - a heap proxy onto the
        //  declared node, exactly as child() does - so it has to be destroyed
        //  like one. Discarding the return leaks the proxy, not the node.
        MsgFieldHandle hDecl = msgcore_field_declare_int(hRoot, L"n", 1, 1);
        TF_CHECK(hDecl != nullptr);
        msgcore_field_destroy(hDecl);

        msgcore_field_destroy(hRoot);

        //  The value is unchanged - it is the same address the caller still
        //  holds - but the API no longer answers to it.
        TF_CHECK_EQ(msgcore_field_exists(hRoot, L"n"), 0);
        TF_CHECK(msgcore_field_child(hRoot, L"n") == nullptr);

        //  Double destroy: refused, not a double free.
        msgcore_field_destroy(hRoot);

        msgcore_mgr_destroy(hMgr);
        TF_CHECK_EQ(msgcore_mgr_is_dirty(hMgr), 0);
        msgcore_mgr_destroy(hMgr);
    }

    TF_CASE("a handle of the wrong kind is refused")
    {
        MsgMgrHandle   hMgr  = msgcore_mgr_create();
        MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
        TF_CHECK(hMgr != nullptr && hRoot != nullptr);

        MsgCursHandle hCurs = msgcore_curs_from_field(hRoot);
        TF_CHECK(hCurs != nullptr);

        //  Each of these is a live handle - of the wrong class. Before the
        //  registry every one of them was a static_cast into a foreign object.
        TF_CHECK_EQ(msgcore_mgr_is_dirty(hRoot), 0);          // field spent as manager
        TF_CHECK(msgcore_mgr_root(hCurs)        == nullptr);  // cursor spent as manager
        TF_CHECK_EQ(msgcore_field_exists(hMgr, L"x"), 0);     // manager spent as field
        TF_CHECK_EQ(msgcore_list_get_count(hRoot), 0);        // field spent as list
        TF_CHECK_EQ(msgcore_vect_get_count(hCurs), 0);        // cursor spent as vector
        TF_CHECK(msgcore_curs_get_field(hRoot)  == nullptr);  // field spent as cursor

        //  Destroying under the wrong kind must not delete the object either -
        //  the handle is still usable afterwards.
        msgcore_curs_destroy(hRoot);
        TF_CHECK_EQ(msgcore_field_exists(hRoot, L"anything"), 0);   // answers, does not crash
        MsgFieldHandle hRedecl = msgcore_field_declare_int(hRoot, L"n", 7, 1);
        TF_CHECK(hRedecl != nullptr);
        msgcore_field_destroy(hRedecl);

        msgcore_curs_destroy(hCurs);
        msgcore_field_destroy(hRoot);
        msgcore_mgr_destroy(hMgr);
    }

    TF_CASE("the registry still says yes to a live handle of the right kind")
    {
        //  The control. Every case above would pass against an API that refused
        //  everything; this is what makes them mean what they say.
        MsgMgrHandle   hMgr  = msgcore_mgr_create();
        MsgFieldHandle hRoot = msgcore_mgr_root(hMgr);
        TF_CHECK(hMgr != nullptr && hRoot != nullptr);

        MsgFieldHandle hLive = msgcore_field_declare_int(hRoot, L"live", 42, 1);
        TF_CHECK(hLive != nullptr);
        msgcore_field_destroy(hLive);
        TF_CHECK_EQ(msgcore_field_exists(hRoot, L"live"), 1);

        MsgFieldHandle hChild = msgcore_field_child(hRoot, L"live");
        TF_CHECK(hChild != nullptr);
        TF_CHECK_EQ(msgcore_field_get_int(hChild), 42);

        MsgCursHandle hCurs = msgcore_curs_from_field(hRoot);
        TF_CHECK(hCurs != nullptr);
        msgcore_curs_destroy(hCurs);

        msgcore_field_destroy(hChild);
        msgcore_field_destroy(hRoot);
        msgcore_mgr_destroy(hMgr);
    }
}

// ---------------------------------------------------------------------------
void RunMsgcoreCApiSuite()
{
    Test_CApi_TypeNames();
    Test_CApi_TypeFromName();
    Test_CApi_LiveVsDetached();
    Test_CApi_PersistThroughSaveLoad();
    Test_CApi_P2PosRoundTrip();
    Test_CApi_Tstamp();
    Test_CApi_RenameChild();
    Test_CApi_MoveChild();
    Test_CApi_RetypeChild();
    Test_CApi_TriggerSink();
    Test_CApi_HandleGuards();
}
