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
// MsgcoreSuite.cpp
//
// Unit tests for the Msgcore data-model library: the typed value cell
// (P3PmsgData), the named field (P3PmsgField), the container types
// (P3PmsgList / P3PmsgVect / P3PmsgAttr / P3PmsgDesc), the value stack
// (MsgStck), the event/exception builder (P2Pevent) and the DATE
// normalisation helpers.
//
// These exercise the same surface the legacy MsgcoreTests.cpp smoke code
// touched, but as isolated, asserted cases.

#include "stdafx.h"

#include "P2Pmsg.h"
#include "P2Pmsg_Ext.h"
#include "MsgAttr.h"
#include "MsgDesc.h"
#include "MsgStck.h"
#include "MsgList.h"
#include "MsgVect.h"
#include "MsgCurs.h"
#include "Msgexception.h"
#include "P2PmsgMgr.h"
#include "P2PmsgBSTR.h"

#include "TestFramework.h"

#include <cmath>

using namespace std;

// ---------------------------------------------------------------------------
// P3PmsgData : typed value cell
// ---------------------------------------------------------------------------
static void Test_Data_TypedValues()
{
    TF_CASE("P3PmsgData holds and round-trips each scalar type")
    {
        P3PmsgData oChar = (char)1;
        oChar.c_char(2);
        TF_CHECK(oChar.c_char() == 2);

        P3PmsgData oShort = (short)1;
        oShort.c_short(7);
        TF_CHECK(oShort.c_short() == 7);

        P3PmsgData oInt = (int)1;
        oInt.c_int(12345);
        TF_CHECK(oInt.c_int() == 12345);

        P3PmsgData oDouble = (double)1.0;
        oDouble.c_double(2.5);
        TF_CHECK(oDouble.c_double() == 2.5);

        P3PmsgData oBool = true;
        TF_CHECK(oBool.c_bool() == true);
        oBool.c_bool(false);
        TF_CHECK(oBool.c_bool() == false);
    }

    TF_CASE("P3PmsgData assignment copies the value and preserves type")
    {
        P3PmsgData oSrc = (int)99;
        P3PmsgData oDst;
        oDst = oSrc;
        TF_CHECK(oDst.c_int() == 99);
        TF_CHECK(oDst.DataType() == oSrc.DataType());
    }

    TF_CASE("P3PmsgData exposes a wide-string value")
    {
        P3PmsgData oStr = L"Hello";
        LPCWSTR pszValue = oStr.c_wstr();
        TF_CHECK(pszValue != nullptr);
        TF_CHECK(wcscmp(pszValue, L"Hello") == 0);
    }
}

// ---------------------------------------------------------------------------
// P3PmsgField : named field = name + data (+ optional Attr/Desc/Stack)
// ---------------------------------------------------------------------------
static void Test_Field_NameAndData()
{
    TF_CASE("P3PmsgField compares equal to its name")
    {
        P3PmsgField oField(L"Johnno");
        TF_CHECK(oField == L"Johnno");
        TF_CHECK(!(oField == L"Somebody"));
    }

    TF_CASE("assigning data to a field changes its data type")
    {
        P3PmsgField oField(L"Johnno");
        int uTypeBefore = oField.DataType();
        oField = P3PmsgData((int)1);
        int uTypeAfter = oField.DataType();
        oField.c_int(42);
        TF_CHECK(oField.c_int() == 42);
        TF_CHECK(uTypeBefore != uTypeAfter);
    }

    TF_CASE("copy-constructed field carries the same data")
    {
        // A field must be given a data cell (here INT) before c_int() may
        // write into it; c_int() on a name-only field has no sized cell.
        P3PmsgField oField(L"Bill");
        oField = P3PmsgData((int)1);
        TF_CHECK(oField.c_int() == 1);

        P3PmsgField oCopy = oField;
        oCopy.AssertValid();
        TF_CHECK(oCopy.c_int() == 1);
    }

    TF_CASE("assigning a name renames the field while keeping its data cell")
    {
        P3PmsgName  oName(L"Larry");
        P3PmsgField oField(L"Bill");
        oField = P3PmsgData((int)0);  // establish an INT data cell
        oField = oName;               // rename only -- cell survives
        oField.c_int(4);
        TF_CHECK(oField == L"Larry");
        TF_CHECK(oField.c_int() == 4);
    }

    TF_CASE("DeclareItem / SelectItem / Exists on a field's descendants")
    {
        P3PmsgField oRoot(L"Root");
        oRoot.DeclareItem(L"Age", P3PmsgData((int)30));
        TF_CHECK(oRoot.Exists(L"Age"));
        TF_CHECK(!oRoot.Exists(L"Missing"));
        TF_CHECK(oRoot.SelectItem(L"Age").c_int() == 30);
    }

    TF_CASE("field name honours the 63-UTF-16-unit bound; overrun throws cleanly (astral counts as 2 units)")
    {
        // The inline name field holds 63 P2PWCHAR units. c_name() enforces this on
        // the live object, so a rejected overrun leaves the prior name intact (no
        // partial write / corruption) -- proven by the post-throw checks. The bound
        // is measured in UTF-16 UNITS, not code points: one astral code point is two
        // units on both OSes (surrogate pair on Windows, an encoded pair from the
        // UTF-32 wchar on the Linux port). c_size() returns the stored unit count.
        auto rejects = []( P3PmsgName& n, const wchar_t* s ) -> bool {
            try { n.c_name( s, 0 ); return false; }
            catch ( P2Pevent* pEVT ) { if ( pEVT ) pEVT->Cancel(false); return true; }  // false: discard silently (no Display/MessageBox on Windows)
        };

        // 63 units: in bounds.
        P3PmsgName oBmp(L"seed");
        oBmp.c_name( std::wstring(63, L'a').c_str(), 0 );
        TF_CHECK(oBmp.c_size() == 63);

        // 64 units: overruns -> clean throw; the live name is untouched.
        P3PmsgName oBmpBad(L"keep");                        // 4 units
        TF_CHECK(rejects( oBmpBad, std::wstring(64, L'a').c_str() ));
        TF_CHECK(oBmpBad.c_size() == 4 && oBmpBad == L"keep");

        // 31 astral chars = 62 units (in bounds); 32 astral chars = 64 units (overruns).
        std::wstring a31; for ( int i = 0; i < 31; ++i ) a31 += L"\U0001F680";
        P3PmsgName oAstral(L"seed");
        oAstral.c_name( a31.c_str(), 0 );
        TF_CHECK(oAstral.c_size() == 62);

        std::wstring a32; for ( int i = 0; i < 32; ++i ) a32 += L"\U0001F680";
        P3PmsgName oAstralBad(L"keep");
        TF_CHECK(rejects( oAstralBad, a32.c_str() ));
        TF_CHECK(oAstralBad.c_size() == 4);
    }
}

// ---------------------------------------------------------------------------
// P3PmsgList : ordered list of data cells
// ---------------------------------------------------------------------------
static void Test_List()
{
    TF_CASE("AddListTail grows the count")
    {
        P3PmsgList oList;
        TF_CHECK_EQ((int)oList.GetCount(), 0);
        oList.AddListTail(P3PmsgData((int)1));
        oList.AddListTail(P3PmsgData((int)2));
        oList.AddListTail(P3PmsgData("Johnno"));
        TF_CHECK_EQ((int)oList.GetCount(), 3);
    }

    TF_CASE("operator += appends like AddListTail")
    {
        P3PmsgList oList;
        oList += P3PmsgData("Susan");
        oList += P3PmsgData("Whoever");
        TF_CHECK_EQ((int)oList.GetCount(), 2);
    }

    TF_CASE("forward iteration visits every element")
    {
        P3PmsgList oList;
        oList.AddListTail(P3PmsgData((int)10));
        oList.AddListTail(P3PmsgData((int)20));
        oList.AddListTail(P3PmsgData((int)30));

        int nVisited = 0;
        int nSum     = 0;
        VBLaddr aPos = oList.GetHeadPos();
        while (aPos)
        {
            P3PmsgData& oData = oList.GetNext(aPos);
            nSum += oData.c_int();
            ++nVisited;
        }
        TF_CHECK_EQ(nVisited, 3);
        TF_CHECK_EQ(nSum, 60);
    }

    TF_CASE("DropTail shrinks the count")
    {
        P3PmsgList oList;
        oList.AddListTail(P3PmsgData((int)1));
        oList.AddListTail(P3PmsgData((int)2));
        oList.DropTail();
        TF_CHECK_EQ((int)oList.GetCount(), 1);
    }

    // AddListHead once omitted the VBLockItem_Init(..., VBLock_Data) its twin
    // AddListTail makes, so the prepended item was linked in with no type tag
    // and the next read of it tripped the ASSERT(0) in VBLockItem_pData.
    TF_CASE("AddListHead prepends a readable item")
    {
        P3PmsgList oList;
        oList.AddListTail(P3PmsgData((int)20));
        oList.AddListTail(P3PmsgData((int)30));
        oList.AddListHead(P3PmsgData((int)10));
        TF_CHECK_EQ((int)oList.GetCount(), 3);

        VBLaddr aPos = oList.GetHeadPos();
        TF_CHECK_EQ(oList.GetNext(aPos).c_int(), 10);
        TF_CHECK_EQ(oList.GetNext(aPos).c_int(), 20);
        TF_CHECK_EQ(oList.GetNext(aPos).c_int(), 30);
        TF_CHECK_EQ(oList.GetTail().c_int(), 30);
    }

    TF_CASE("AddListHead into an empty list is also the tail")
    {
        P3PmsgList oList;
        oList.AddListHead(P3PmsgData((int)42));
        TF_CHECK_EQ((int)oList.GetCount(), 1);
        TF_CHECK_EQ(oList.GetTail().c_int(), 42);
        TF_CHECK(oList.GetHeadPos() == oList.GetTailPos());
    }

    // GetPrev was declared in MsgList.h but never defined -- an unresolved
    // external for any caller. It is the mirror of GetNext: it steps back over
    // the cell it returns, and the position falls to 0 past the head.
    TF_CASE("backward iteration visits every element in reverse")
    {
        P3PmsgList oList;
        oList.AddListTail(P3PmsgData((int)10));
        oList.AddListTail(P3PmsgData((int)20));
        oList.AddListTail(P3PmsgData((int)30));

        int nVisited = 0;
        int nSum     = 0;
        int aSeen[3] = { 0, 0, 0 };
        VBLaddr aPos = oList.GetTailPos();
        while (aPos)
        {
            P3PmsgData& oData = oList.GetPrev(aPos);
            if (nVisited < 3)
                aSeen[nVisited] = oData.c_int();
            nSum += oData.c_int();
            ++nVisited;
        }
        TF_CHECK_EQ(nVisited, 3);
        TF_CHECK_EQ(nSum, 60);
        TF_CHECK_EQ(aSeen[0], 30);
        TF_CHECK_EQ(aSeen[1], 20);
        TF_CHECK_EQ(aSeen[2], 10);
    }

    TF_CASE("a single-element list walks both ways")
    {
        P3PmsgList oList;
        oList.AddListTail(P3PmsgData((int)7));

        VBLaddr aFwd = oList.GetHeadPos();
        TF_CHECK_EQ(oList.GetNext(aFwd).c_int(), 7);
        TF_CHECK(aFwd == 0);

        VBLaddr aRev = oList.GetTailPos();
        TF_CHECK_EQ(oList.GetPrev(aRev).c_int(), 7);
        TF_CHECK(aRev == 0);
    }
}

// ---------------------------------------------------------------------------
// P3PmsgVect : random-access vector of typed elements
// ---------------------------------------------------------------------------
static void Test_Vect()
{
    TF_CASE("constructed vector has the requested element count")
    {
        P3PmsgVect oVect(3, L"Elem", P3PmsgData((int)0));
        TF_CHECK_EQ((int)oVect.GetCount(), 3);
    }

    TF_CASE("elements are addressable and independently mutable by index")
    {
        P3PmsgVect oVect(3, L"Elem", P3PmsgData((int)0));
        oVect.r_data(0).c_int(100);
        oVect.r_data(1).c_int(200);
        oVect.r_data(2).c_int(300);

        TF_CHECK(oVect.r_data(0).c_int() == 100);
        TF_CHECK(oVect.r_data(1).c_int() == 200);
        TF_CHECK(oVect.r_data(2).c_int() == 300);
        TF_CHECK(oVect.IsField(0));   // elements are named fields, not bare data cells
    }

    TF_CASE("out-of-range Goto fails without crashing")
    {
        P3PmsgVect oVect(2, L"Elem", P3PmsgData((int)0));
        TF_CHECK(oVect.Goto(0) != 0);
        TF_CHECK(oVect.Goto(2) == 0);
        TF_CHECK(oVect.Goto(-1) == 0);
    }

    TF_CASE("InsertAt appends and inserts, shifting later elements")
    {
        P3PmsgVect oVect(0, L"Elem", P3PmsgData((int)0));
        TF_CHECK_EQ((int)oVect.GetCount(), 0);
        oVect.InsertAt(0, P3PmsgField(L"e", P3PmsgData((int)10)));   // [10]
        oVect.InsertAt(1, P3PmsgField(L"e", P3PmsgData((int)30)));   // [10,30]
        oVect.InsertAt(1, P3PmsgField(L"e", P3PmsgData((int)20)));   // [10,20,30]
        TF_CHECK_EQ((int)oVect.GetCount(), 3);
        TF_CHECK(oVect.r_data(0).c_int() == 10);
        TF_CHECK(oVect.r_data(1).c_int() == 20);
        TF_CHECK(oVect.r_data(2).c_int() == 30);
    }

    TF_CASE("Delete removes an element and compacts the rest")
    {
        P3PmsgVect oVect(0, L"Elem", P3PmsgData((int)0));
        for (int i = 0; i < 4; i++)
            oVect.InsertAt(i, P3PmsgField(L"e", P3PmsgData((int)(i + 1))));  // [1,2,3,4]
        TF_CHECK(oVect.Delete(1));                                          // [1,3,4]
        TF_CHECK_EQ((int)oVect.GetCount(), 3);
        TF_CHECK(oVect.r_data(0).c_int() == 1);
        TF_CHECK(oVect.r_data(1).c_int() == 3);
        TF_CHECK(oVect.r_data(2).c_int() == 4);
        TF_CHECK(!oVect.Delete(9));                                        // out of range
    }

    TF_CASE("Truncate empties the vector")
    {
        P3PmsgVect oVect(5, L"Elem", P3PmsgData((int)7));
        TF_CHECK_EQ((int)oVect.GetCount(), 5);
        oVect.Truncate();
        TF_CHECK_EQ((int)oVect.GetCount(), 0);
    }

    TF_CASE("copy-assignment deep-copies every element")
    {
        P3PmsgVect oVect(3, L"Elem", P3PmsgData((int)0));
        oVect.r_data(0).c_int(11);
        oVect.r_data(1).c_int(22);
        oVect.r_data(2).c_int(33);

        P3PmsgVect oCopy(0, L"Copy", P3PmsgData((int)0));
        oCopy = oVect;
        TF_CHECK_EQ((int)oCopy.GetCount(), 3);
        TF_CHECK(oCopy.r_data(0).c_int() == 11);
        TF_CHECK(oCopy.r_data(2).c_int() == 33);

        // Mutating the copy must not disturb the original (independent storage).
        oCopy.r_data(0).c_int(99);
        TF_CHECK(oVect.r_data(0).c_int() == 11);
    }

    TF_CASE("overflow past 32 elements spills into aExtra continuation blocks")
    {
        // 70 elements spans the inline aAlloc[32] plus two continuation blocks.
        P3PmsgVect oVect(0, L"Elem", P3PmsgData((int)0));
        for (int i = 0; i < 70; i++)
            oVect.InsertAt(i, P3PmsgField(L"e", P3PmsgData((int)(i * 10))));
        TF_CHECK_EQ((int)oVect.GetCount(), 70);
        TF_CHECK(oVect.r_data(0).c_int()  == 0);
        TF_CHECK(oVect.r_data(31).c_int() == 310);   // last inline slot
        TF_CHECK(oVect.r_data(32).c_int() == 320);   // first continuation slot
        TF_CHECK(oVect.r_data(63).c_int() == 630);   // spans into 2nd continuation
        TF_CHECK(oVect.r_data(69).c_int() == 690);

        // Insert near the boundary shifts elements across the block seam.
        oVect.InsertAt(32, P3PmsgField(L"e", P3PmsgData((int)9999)));
        TF_CHECK_EQ((int)oVect.GetCount(), 71);
        TF_CHECK(oVect.r_data(32).c_int() == 9999);
        TF_CHECK(oVect.r_data(33).c_int() == 320);   // former [32] pushed right
        TF_CHECK(oVect.r_data(70).c_int() == 690);
    }

    TF_CASE("nested vector element is deep-copied and independently addressable")
    {
        P3PmsgVect oInner(2, L"Inner", P3PmsgData((int)0));
        oInner.r_data(0).c_int(7);
        oInner.r_data(1).c_int(8);

        P3PmsgVect oOuter(0, L"Outer", P3PmsgData((int)0));
        oOuter.InsertAt(0, P3PmsgField(L"scalar", P3PmsgData((int)1)));
        oOuter.InsertAt(1, oInner);                 // element 1 is itself a vect
        TF_CHECK_EQ((int)oOuter.GetCount(), 2);
        TF_CHECK(oOuter.IsVect(1));
        TF_CHECK_EQ((int)oOuter.r_vect(1).GetCount(), 2);
        TF_CHECK(oOuter.r_vect(1).r_data(1).c_int() == 8);

        // Mutating the original inner must not affect the copy held by oOuter.
        oInner.r_data(1).c_int(99);
        TF_CHECK(oOuter.r_vect(1).r_data(1).c_int() == 8);
    }

    TF_CASE("a vect round-trips through a P3PmsgDesc container")
    {
        P3PmsgVect oVect(3, L"Payload", P3PmsgData((int)0));
        oVect.r_data(0).c_int(5);
        oVect.r_data(1).c_int(6);
        oVect.r_data(2).c_int(7);

        P3PmsgField oHolder(L"Holder");
        oHolder.r_Desc(P3PmsgField::AttrCMD_Create);
        oHolder.r_Desc() += oVect;                  // PushBack deep-copies the vect
        TF_CHECK(oHolder.r_Desc().Exists(L"Payload"));

        P3PmsgVect oBack(oHolder.r_Desc().SelectVect(L"Payload").r_Object());
        TF_CHECK_EQ((int)oBack.GetCount(), 3);
        TF_CHECK(oBack.r_data(0).c_int() == 5);
        TF_CHECK(oBack.r_data(2).c_int() == 7);
    }

    TF_CASE("a vect persists across a P2PmsgMgr save/load (IOMAGE heap)")
    {
        wchar_t szDir[MAX_PATH]  = { 0 };
        wchar_t szPath[MAX_PATH] = { 0 };
        GetTempPathW(MAX_PATH, szDir);
        swprintf_s(szPath, MAX_PATH, L"%smscs_vect_persist.p2p", szDir);

        try
        {
            // Build a vect inside an IOMAGE-backed manager and save it. The
            // manager stores VBLock addresses as image offsets, so aAlloc[]
            // must survive serialisation.
            {
                P2PmsgMgr   oMgr(VBLock_Addr64, 4096, 1u << 20);
                P3PmsgVect  oVect(4, L"Persisted", P3PmsgData((int)0));
                for (int i = 0; i < 4; i++)
                    oVect.r_data(i).c_int((i + 1) * 100);
                oMgr.r_Desc(P3PmsgField::AttrCMD_Create);
                oMgr.r_Desc() += oVect;
                oMgr.Save(szPath);
            }
            // Reload into a fresh manager and read the vect back.
            {
                P2PmsgMgr oMgr(szPath);
                P3PmsgVect oBack(oMgr.r_Desc().SelectVect(L"Persisted").r_Object());
                TF_CHECK_EQ((int)oBack.GetCount(), 4);
                TF_CHECK(oBack.r_data(0).c_int() == 100);
                TF_CHECK(oBack.r_data(3).c_int() == 400);
            }
        }
        catch (P2Pevent* pEVT)
        {
            tf_fail(__FILE__, __LINE__, "unexpected P2Pevent during persistence");
            pEVT->Cancel(false);
        }
        _wremove(szPath);
    }
}

// ---------------------------------------------------------------------------
// P3PmsgAttr / P3PmsgDesc : attribute (@keyed) and descendant containers
// ---------------------------------------------------------------------------
static void Test_AttrDesc()
{
    TF_CASE("attributes can be created, populated and queried")
    {
        P3PmsgField oField(L"Larry", DataBSTR08(L"Data"));
        oField.r_Attr(P3PmsgField::AttrCMD_Create) += P3PmsgField(L"Johnno");
        oField.AssertValid();
        TF_CHECK(oField.r_Attr().Exists(L"Johnno"));
        TF_CHECK(!oField.r_Attr().Exists(L"Nobody"));
    }

    TF_CASE("descendants accept fields and a list")
    {
        P3PmsgList oList;
        oList += P3PmsgData("a");
        oList += P3PmsgData("b");

        P3PmsgItem oItem;
        oItem.r_name() = _N("TestNodeName");
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        oItem.r_Desc() += P3PmsgField(L"Johnno");
        oItem.r_Desc() += P3PmsgField(L"Bill");
        oItem.r_Desc() += oList;
        oItem.AssertValid();
        TF_CHECK(oItem.r_Desc().Exists(L"Johnno"));
        TF_CHECK(oItem.r_Desc().Exists(L"Bill"));

        P3PmsgItem oCopy;
        oCopy = oItem;                // deep copy must not corrupt the source
        oItem.AssertValid();
        oCopy.AssertValid();
        TF_CHECK(oCopy.r_Desc().Exists(L"Johnno"));
    }
}

// ---------------------------------------------------------------------------
// P3PmsgCurs::Goto : the search key must survive the walk
// ---------------------------------------------------------------------------
static void Test_Curs_GotoKeyLifetime()
{
    // Off Win32 a name obtained from c_name() is a slot of the 16-entry
    // thread-local widening ring (p2p_wstr_from_store, Platform/p2pstr.h), and
    // every sibling Goto compares spends one more slot -- so the budget is not
    // 16 calls the caller can count, it is 16 SIBLINGS. Past that the key is
    // rewritten with the CURRENT sibling's name while it is being compared
    // against, the comparison reads a buffer against itself, and the scan stops
    // on the WRONG item while reporting success. Goto snapshots its key
    // (p2p_wkey) precisely so that no caller can cause this.
    //
    // On Win32 c_name() returns the store pointer and there is no ring, so this
    // case passes with or without the snapshot there. It is the Linux build that
    // can fail it -- which is why it asserts the found item's IDENTITY, not just
    // that something was found.
    TF_CASE("Goto(name) honours a key that lives in the widening ring")
    {
        const int kItems = 24;               // comfortably past the ring's 16 slots

        P3PmsgItem oItem;
        oItem.r_name() = _N("GotoKeyLifetime");
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        for ( int i = 0; i < kItems; i++ )
        {
          wchar_t szName[32];
          swprintf_s(szName, 32, L"Item%02d", i);
          oItem.r_Desc() += P3PmsgField(szName);
        }
        TF_CHECK_EQ((int)oItem.r_Desc().GetCount(), kItems);

        // Park a second cursor on the LAST descendant and hand Goto its bare
        // c_name() -- a live ring slot, deliberately NOT copied first.
        P3PmsgCurs oCursKey(oItem.r_Desc());
        TF_CHECK(oCursKey.Goto(kItems - 1));
        LPCTNAM lpszKey = oCursKey.r_name().c_name();

        P3PmsgCurs oCurs(oItem.r_Desc());
        TF_CHECK(oCurs.Goto(lpszKey));
        TF_CHECK_EQ((int)oCurs.Item(), kItems - 1);
        TF_CHECK(CString(oCurs.r_name().c_name()).Compare(L"Item23") == 0);
    }

    // Goto snapshots its own key, but a scan that drives the cursor itself and
    // compares as it goes owns the hazard: P3PmsgRefactor_Rename spends a ring
    // slot per sibling in ITS loop, and consumes the NEW name inside that loop,
    // after those comparisons -- so a recycled key renames to the wrong name,
    // not merely at the wrong place.
    TF_CASE("Rename honours keys that live in the widening ring")
    {
        const int kItems = 24;

        P3PmsgItem oItem;
        oItem.r_name() = _N("RenameKeyLifetime");
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        for ( int i = 0; i < kItems; i++ )
        {
          wchar_t szName[32];
          swprintf_s(szName, 32, L"Item%02d", i);
          oItem.r_Desc() += P3PmsgField(szName);
        }

        // Both arguments are bare c_name() pointers, deliberately not copied.
        P3PmsgCurs oCursOld(oItem.r_Desc());
        TF_CHECK(oCursOld.Goto(kItems - 1));          // rename the LAST one
        LPCTNAM lpszOld = oCursOld.r_name().c_name();

        P3PmsgItem oNewName;
        oNewName.r_name() = _N("Renamed");
        LPCTNAM lpszNew = oNewName.r_name().c_name();

        P3PmsgRefactor_Rename ( oItem, lpszOld, lpszNew );

        TF_CHECK(oItem.r_Desc().Exists(_N("Renamed")));
        TF_CHECK(!oItem.r_Desc().Exists(_N("Item23")));
        // Every other name must be untouched: a recycled key renames a
        // bystander instead of, or as well as, the intended item.
        for ( int i = 0; i < kItems - 1; i++ )
        {
          wchar_t szName[32];
          swprintf_s(szName, 32, L"Item%02d", i);
          TF_CHECK(oItem.r_Desc().Exists(szName));
        }
        TF_CHECK_EQ((int)oItem.r_Desc().GetCount(), kItems);
    }

    //  The third member of this class. Session 26 fixed its key by inspection;
    //  guarding it took first finding out why it could not find anything by
    //  name at all -- c_wcsicmpWC() is a PREDICATE (non-zero = matches), and
    //  both name tests in P3Pmsg_FindChildWithAttr read it as a wcsicmp-style
    //  comparison, so the function skipped exactly the children that matched.
    //  With that corrected the child is found in the first loop, which is the
    //  loop that spends a ring slot per sibling.
    //
    //  Same platform note as the two above: on Win32 c_name() is the store
    //  pointer and there is no ring, so this passes there either way. It
    //  asserts the found object's IDENTITY so the Linux build can fail it.
    TF_CASE("FindChildWithAttr honours keys that live in the widening ring")
    {
        const int kItems = 24;

        //  Exactly ONE sibling carries the attribute, and it is the LAST one -
        //  so a key recycled part-way through the scan matches a bystander that
        //  does not have it, or stops on a name it never was.
        P3PmsgItem oItem;
        oItem.r_name() = _N("FindChildKeyLifetime");
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        for ( int i = 0; i < kItems; i++ )
        {
          wchar_t szName[32];
          swprintf_s(szName, 32, L"Item%02d", i);
          P3PmsgField oChild(szName);
          if ( i == kItems - 1 )
            oChild.r_Attr(P3PmsgField::AttrCMD_Create) += P3PmsgField(_N("Marked"));
          oItem.r_Desc() += oChild;
        }

        //  Both keys are bare c_name() pointers - live ring slots, not copies.
        P3PmsgCurs oCursKey(oItem.r_Desc());
        TF_CHECK(oCursKey.Goto(kItems - 1));
        LPCTNAM lpszChild = oCursKey.r_name().c_name();

        P3PmsgItem oAttrName;
        oAttrName.r_name() = _N("Marked");
        LPCTNAM lpszAttr = oAttrName.r_name().c_name();

        P3PmsgObject oFound =
            P3Pmsg_FindChildWithAttr ( oItem, lpszAttr, lpszChild );

        TF_CHECK(!oFound.IsVoid());
        if (!oFound.IsVoid())
        {
          P3PmsgField oFoundField = oFound;
          TF_CHECK(oFoundField == L"Item23");
        }
    }

    //  The name test's SENSE, pinned separately from the ring: a name that
    //  matches must be found, and a name that matches nothing must not come
    //  back with some other child that merely has the attribute. Before the
    //  correction the first of these returned void and the second returned the
    //  marked child - both exactly backwards.
    TF_CASE("FindChildWithAttr matches the name it is given, not the others")
    {
        P3PmsgItem oItem;
        oItem.r_name() = _N("FindChildSense");
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        for ( int i = 0; i < 4; i++ )
        {
          wchar_t szName[32];
          swprintf_s(szName, 32, L"Kid%d", i);
          P3PmsgField oChild(szName);
          if ( i == 2 )
            oChild.r_Attr(P3PmsgField::AttrCMD_Create) += P3PmsgField(_N("Tag"));
          oItem.r_Desc() += oChild;
        }

        P3PmsgObject oHit = P3Pmsg_FindChildWithAttr ( oItem, _N("Tag"), _N("Kid2") );
        TF_CHECK(!oHit.IsVoid());
        if (!oHit.IsVoid())
        {
          P3PmsgField oHitField = oHit;
          TF_CHECK(oHitField == L"Kid2");
        }

        //  A wildcard that matches the marked child.
        P3PmsgObject oWild = P3Pmsg_FindChildWithAttr ( oItem, _N("Tag"), _N("Kid*") );
        TF_CHECK(!oWild.IsVoid());

        //  No name given at all - the documented default - still finds it.
        P3PmsgObject oAny = P3Pmsg_FindChildWithAttr ( oItem, _N("Tag") );
        TF_CHECK(!oAny.IsVoid());
    }

    //  A search that matches NOTHING must come back VOID. That is how every
    //  "not found" in this API is reported, and it did not work: the caller's
    //  copy of a void P3PmsgObject was not void, because the copy CONSTRUCTOR
    //  took its inline-block branch for a void source and pointed m_aVBLock at
    //  the copy's own block (Msgcore P2Pmsg.cpp). operator=() was already right
    //  - Connect() has nullified for a void source since 2025-02-18 - so
    //  `oA = oB` behaved and `P3PmsgObject oA = oB` did not, which is every
    //  by-value return.
    //
    //  Three misses, because they fail at three different points: no child of
    //  that name; a child of that name without the attribute; neither.
    TF_CASE("FindChildWithAttr returns void for a search that matches nothing")
    {
        P3PmsgItem oItem;
        oItem.r_name() = _N("FindChildMiss");
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        for ( int i = 0; i < 4; i++ )
        {
          wchar_t szName[32];
          swprintf_s(szName, 32, L"Kid%d", i);
          P3PmsgField oChild(szName);
          if ( i == 2 )
            oChild.r_Attr(P3PmsgField::AttrCMD_Create) += P3PmsgField(_N("Tag"));
          oItem.r_Desc() += oChild;      // all four are LEAVES - no r_Desc()
        }

        P3PmsgObject oNoName  = P3Pmsg_FindChildWithAttr ( oItem, _N("Tag"),        _N("Nobody") );
        P3PmsgObject oNoAttr  = P3Pmsg_FindChildWithAttr ( oItem, _N("NoSuchAttr"), _N("Kid1")   );
        P3PmsgObject oNeither = P3Pmsg_FindChildWithAttr ( oItem, _N("NoSuchAttr"), _N("Nobody") );
        TF_CHECK(oNoName.IsVoid());
        TF_CHECK(oNoAttr.IsVoid());
        TF_CHECK(oNeither.IsVoid());
    }

    //  The same defect stated at the level it actually lives at: copying a void
    //  P3PmsgObject must produce a void one, whichever way the copy is spelled.
    //  Both spellings are checked because only ONE of them was broken.
    TF_CASE("a void P3PmsgObject stays void through copy and assignment")
    {
        P3PmsgObject oVoid;
        TF_CHECK(oVoid.IsVoid());

        P3PmsgObject oCopied = oVoid;      // copy CONSTRUCTOR - this was the bug
        TF_CHECK(oCopied.IsVoid());

        P3PmsgObject oAssigned;
        oAssigned = oVoid;                 // operator= - already correct
        TF_CHECK(oAssigned.IsVoid());

        //  And a copy of a copy, since the broken branch made its result look
        //  like a standalone object that would then propagate.
        P3PmsgObject oTwice = oCopied;
        TF_CHECK(oTwice.IsVoid());
    }

    //  Why this matters beyond one search function: THREE Exists() overloads -
    //  P3PmsgField (P2Pmsg.cpp:3332), P3PmsgNode (:4267) and P3PmsgDesc
    //  (MsgDesc.cpp:394) - all answer
    //      !P3Pmsg_SelectObject(&r_Object(), name).IsVoid()
    //  on a P3PmsgObject returned BY VALUE. Any of those returns whose copy is
    //  not elided would report "exists" for a name that does not.
    TF_CASE("Exists() says no to a name that is not there")
    {
        P3PmsgItem oItem;
        oItem.r_name() = _N("ExistsHost");
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        oItem.r_Desc() += P3PmsgField(_N("Present"));

        TF_CHECK(oItem.r_Desc().Exists(_N("Present")));
        TF_CHECK(!oItem.r_Desc().Exists(_N("Absent")));

        //  And through the field-level overload, which is the one most callers
        //  reach for.
        TF_CHECK(oItem.Exists(_N("Present")));
        TF_CHECK(!oItem.Exists(_N("Absent")));
    }
}

// ---------------------------------------------------------------------------
// MsgStck : per-field value stack (push a value, mutate, pop to restore)
// ---------------------------------------------------------------------------
static void Test_Stack()
{
    TF_CASE("push/pop restores the field's prior name")
    {
        P3PmsgField oField(L"Larry", DataBSTR08(L"Data"));
        oField.r_Stck().Push();
        oField = P3PmsgName(L"Larry-Pushed");
        TF_CHECK(oField == L"Larry-Pushed");

        if (oField.IsStacked())
            oField.r_Stck().Pop();
        oField.AssertValid();
        TF_CHECK(oField == L"Larry");
    }
}

// ---------------------------------------------------------------------------
// P2Pevent : fluent event / exception builder
// ---------------------------------------------------------------------------
static void Test_Event()
{
    TF_CASE("MakeEvent builds an ERROR-class event")
    {
        P2Pevent* pEVT = P2Pevent::MakeEvent(P2Pevent_ERROR);
        TF_CHECK(pEVT != nullptr);
        TF_CHECK(pEVT->GetClass() == P2Pevent_ERROR);
        pEVT->Cancel(false);
    }

    TF_CASE("a wide format renders wide and narrow arguments in full")
    {
        //  The defect this guards: a bare "..." literal is NARROW in this tree,
        //  so Message("[%s]", wideArg) selects the NARROW overload, where %s
        //  means a narrow string. Off Win32 the wide argument is then read as
        //  char* and stops at its first embedded NUL -- after ONE character --
        //  and the specs it never consumed leak into the text as a literal %s.
        //  It truncates on Windows too. _N(...) selects the wide overload,
        //  where p2p_fix_wformat maps %s to %ls for glibc and MSVC takes it
        //  natively; a genuinely narrow argument such as __FUNCTION__ is %hs
        //  there, whose 'h' p2p_fix_wformat erases for the same reason.
        P2Pevent* pEVT = EVERR->Message(_N("addr=[%s] fn=[%hs]"),
                                        _N("Alpha.Bravo"), "TheFunction");
        TF_CHECK(pEVT != nullptr);
        if ( pEVT )
        {
          const CString strMsg = pEVT->GetMessage();
          TF_CHECK(strMsg.Find(_N("Alpha.Bravo")) >= 0);   // not just "A"
          TF_CHECK(strMsg.Find(_N("TheFunction")) >= 0);   // narrow arg, via %hs
          TF_CHECK(strMsg.Find(_N("%s"))          <  0);   // nothing left unconsumed
          pEVT->Cancel(false);
        }
    }

    TF_CASE("fluent setters round-trip through the getters")
    {
        P2Pevent* pEVT = EVERR->Module("Module")
                              ->Message("Message")
                              ->Group("Group")
                              ->Advice("Advice");
        TF_CHECK(pEVT != nullptr);

        //  GetModule()/GetGroup() end in P3PmsgData::c_wstr(), i.e. in
        //  p2p_wstr_from_store(), whose result off Win32 is a slot of a 16-entry
        //  thread-local RING (Platform/p2pstr.h:629-651).  Each of the four
        //  getters spends several slots of its own - Exists() and operator[] both
        //  rescan the event BY NAME and every comparison widens one name, and
        //  GetMessage()/GetAdvice() widen once per list entry besides - so
        //  holding all four raw leaves the first read a couple of calls short of
        //  being recycled.  Copy the two that ARE ring pointers;
        //  GetMessage()/GetAdvice() return const CString& into P2Pevent's own
        //  members and are stable either way.  Byte-identical on Win32.
        CString strModule   = pEVT->GetModule();
        CString strGroup    = pEVT->GetGroup();
        LPCTSTR lpszModule  = strModule;
        LPCTSTR lpszMessage = pEVT->GetMessage();
        LPCTSTR lpszGroup   = strGroup;
        LPCTSTR lpszAdvice  = pEVT->GetAdvice();

        TF_CHECK(lpszModule  != nullptr && wcslen(lpszModule)  > 0);
        TF_CHECK(lpszMessage != nullptr && wcslen(lpszMessage) > 0);
        TF_CHECK(lpszGroup   != nullptr && wcslen(lpszGroup)   > 0);
        TF_CHECK(lpszAdvice  != nullptr && wcslen(lpszAdvice)  > 0);

        TF_CHECK(wcscmp(lpszGroup, L"Group") == 0);

        pEVT->Cancel(false);
    }

    TF_CASE("AFP attaches typed function parameters without loss")
    {
        int   vInt   = 2;
        short vShort = 3;
        P2Pevent* pEVT = EVERR->Module("Mod")
                              ->AFP(vInt)->AFP(vShort)
                              ->Message("Message")->Group("Group")->Advice("Advice");
        TF_CHECK(pEVT != nullptr);
        pEVT->AssertValid();
        pEVT->Cancel(false);
    }

    TF_CASE("copy-constructed event carries the same fields")
    {
        P2Pevent* pEVT = EVERR->Module("Module")
                              ->Message("Message")->Group("Group")->Advice("Advice");
        P2Pevent* pCopy = new P2Pevent(*pEVT);
        TF_CHECK(wcscmp(pEVT->GetGroup(), pCopy->GetGroup()) == 0);
        delete pCopy;
        pEVT->Cancel(false);
    }
}

// ---------------------------------------------------------------------------
// Test_DateNormalisation was here and is REMOVED (2026-08-19).
//
// It exercised DATE2Normalised / Normalised2DATE, which live in COleTime_Ext.h
// in the MsgcoreMFC component. MsgcoreMFC is not part of any repository this
// suite is built from and is not published with them, so those two cases tested
// code a reader of this tree cannot see, through a header they cannot include.
//
// Dropped rather than stubbed, which is the same call Msgcore's own suite made
// for the same cases -- and the reason the shim went too. linux-shim/ defined
// both helpers as IDENTITY functions, so on Linux the monotonic case compared
// three plain doubles and the round-trip case inverted nothing: two cases and
// eight checks that passed while testing nothing at all. A stub that always
// passes is worse than an absent case, because it reads like coverage.
//
// The case count is 2 cases / 8 checks lighter than before. That is the honest
// number, and on Linux it was always the real one.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// P2PmsgData_var (COM VARIANT bridge): the WSTR cases return the wide value.
// On Linux the cell is 16-bit P2PWCHAR storage; the variant must widen it to
// native wchar_t rather than reinterpret the raw store pointer (LinuxPortPlan
// §4.2 — the deferred variant/display path). Exercise it through the public
// P2PmsgData_var() so a wrong reinterpret shows up as a corrupted string.
// ---------------------------------------------------------------------------
static void Test_VariantWideString()
{
    TF_CASE("P2PmsgData_var widens a BMP wide-string value")
    {
        const wchar_t* kText = L"Hello, €uro world";   // includes U+20AC euro
        P3PmsgData oData(kText);
        _variant_t  var  = P2PmsgData_var(oData);
        _bstr_t     bstr(var);
        const wchar_t* got = (const wchar_t*)bstr;
        TF_CHECK(got != nullptr && wcscmp(got, kText) == 0);
    }

    TF_CASE("P2PmsgData_var widens an astral wide-string value")
    {
        const wchar_t* kAstral = L"A\U0001F680€B";     // surrogate pair on Windows
        P3PmsgData oData(kAstral);
        _variant_t  var  = P2PmsgData_var(oData);
        _bstr_t     bstr(var);
        const wchar_t* got = (const wchar_t*)bstr;
        TF_CHECK(got != nullptr && wcscmp(got, kAstral) == 0);
    }
}

// ---------------------------------------------------------------------------
// P3PmsgData copy semantics
//
// P3PmsgData owns its cell through a raw pointer and deletes it in the
// destructor, but declared no copy constructor -- so the compiler generated a
// shallow one and two objects ended up owning the same cell. The source read
// back as zero once the copy died, and the second destructor faulted.
// ---------------------------------------------------------------------------
static void Test_Data_CopySemantics()
{
    TF_CASE("a copied data cell carries the value and the type")
    {
        P3PmsgData oSrc((int)4210);
        P3PmsgData oCopy(oSrc);
        TF_CHECK_EQ(oCopy.DataType(), (VBLockType)VBLockData_INT32);
        TF_CHECK_EQ(oCopy.c_int(), 4210);
    }

    TF_CASE("the copy is independent of the source")
    {
        P3PmsgData oSrc((int)10);
        P3PmsgData oCopy(oSrc);
        oCopy.c_int(99);
        TF_CHECK_EQ(oCopy.c_int(), 99);
        TF_CHECK_EQ(oSrc.c_int(), 10);
    }

    TF_CASE("the source outlives a destroyed copy intact")
    {
        P3PmsgData oSrc((int)7);
        { P3PmsgData oCopy(oSrc); TF_CHECK_EQ(oCopy.c_int(), 7); }
        TF_CHECK_EQ(oSrc.c_int(), 7);          // shallow copy read 0 here
    }

    TF_CASE("copying works for a string cell too")
    {
        P3PmsgData oSrc(L"a value");
        P3PmsgData oCopy(oSrc);
        TF_CHECK(wcscmp(oCopy.c_wstr(), L"a value") == 0);
    }
}

// ---------------------------------------------------------------------------
// P3PmsgTime and the scalar tags the sizeof ladder used to omit
// ---------------------------------------------------------------------------
static void Test_Time()
{
    TF_CASE("P3PmsgTime carries the TIME64 tag, not INT64")
    {
        P3PmsgTime oTime((__int64)1786249800);
        TF_CHECK_EQ(oTime.DataType(), (VBLockType)VBLockData_TIME64);
        TF_CHECK(!oTime.IsNull());
    }

    TF_CASE("c_time64 reads both 64-bit tags")
    {
        P3PmsgTime oTime((__int64)1786249800);
        P3PmsgData oInt((__int64)1786249800);
        TF_CHECK_EQ(oTime.c_time64(), (__int64)1786249800);
        TF_CHECK_EQ(oInt.c_time64(),  (__int64)1786249800);
    }

    TF_CASE("a default-constructed time is null but still typed")
    {
        P3PmsgTime oNull;
        TF_CHECK_EQ(oNull.DataType(), (VBLockType)VBLockData_TIME64);
        TF_CHECK(oNull.IsNull());
    }

    TF_CASE("assigning a time copies value, tag and null flag")
    {
        P3PmsgTime oSrc((__int64)1786249800);
        P3PmsgTime oDst;
        oDst = oSrc;
        TF_CHECK_EQ(oDst.DataType(), (VBLockType)VBLockData_TIME64);
        TF_CHECK_EQ(oDst.c_time64(), (__int64)1786249800);
        TF_CHECK(!oDst.IsNull());
    }

    // VBLockData_Sizeof_uv's scalar ladder handled INT/UINT/DOUBLE only, so
    // assigning any of these sized the copy from a fall-through.
    TF_CASE("float, bool and wchar cells survive assignment")
    {
        P3PmsgData oF((float)1.5f), oB(true), oW((wchar_t)L'Z');
        P3PmsgData oFd, oBd, oWd;
        oFd = oF;  oBd = oB;  oWd = oW;
        TF_CHECK_EQ(oFd.c_float(), 1.5f);
        TF_CHECK_EQ(oBd.c_bool(), true);
        TF_CHECK_EQ(oWd.c_wchar(), (wchar_t)L'Z');
    }
}

// ---------------------------------------------------------------------------
// 64-bit heap addressing
//
// The VBHeapRoot control-key accessors had Addr32/16/08 ladders; most were
// missing the Addr64 case and fell through to ASSERT(0) plus a "corruption"
// throw, so a 64-bit-addressed heap could not be built through P3PmsgBSTR.
// ---------------------------------------------------------------------------
static void Test_HeapWidths()
{
    TF_CASE("a manager can be built at every addressing width")
    {
        P2PmsgMgr16 oMgr16;
        P2PmsgMgr32 oMgr32;
        P2PmsgMgr64 oMgr64;
        TF_CHECK(oMgr16.IsValid());
        TF_CHECK(oMgr32.IsValid());
        TF_CHECK(oMgr64.IsValid());
    }

    TF_CASE("a 64-bit heap holds and returns a tree")
    {
        P2PmsgMgr64 oMgr;
        oMgr.r_Desc(P3PmsgField::AttrCMD_Create);
        oMgr.DeclareItem(L"Alpha", P3PmsgData((int)1));
        oMgr.DeclareItem(L"Beta",  P3PmsgData(L"two"));
        TF_CHECK_EQ((int)oMgr.r_Desc().GetCount(), 2);
        TF_CHECK_EQ(oMgr.SelectItem(L"Alpha").c_int(), 1);
    }
}

// ---------------------------------------------------------------------------
// VBListIOmage::oSync : endian sentinel (byte_order.md §4)
// ---------------------------------------------------------------------------

// Portable byte swap -- deliberately shift-based rather than _byteswap_ulong /
// __builtin_bswap32 so this case builds identically on both toolchains.
static UINT32 tf_bswap32 ( UINT32 v )
{
    return ( (v & 0x000000FFu) << 24 )
         | ( (v & 0x0000FF00u) <<  8 )
         | ( (v & 0x00FF0000u) >>  8 )
         | ( (v & 0xFF000000u) >> 24 );
}

static void Test_IOmageEndianSentinel()
{
    TF_CASE("VBLock_SyncMake stamps size, addressing mode and sentinel")
    {
        const UINT32 w = VBLock_SyncMake ( 0x50, VBLock_Addr32 );
        TF_CHECK_EQ((int)(w & 0x00FFFFFF), 0x50);
        TF_CHECK_EQ((int)VBLock_SyncAddr(w), (int)VBLock_Addr32);
        TF_CHECK_EQ(VBLock_SyncForm(w), VBLockSync_Native);
    }

    TF_CASE("a pre-sentinel header is still accepted as legacy")
    {
        // Exactly what the old writer emitted: size | uAddrType<<24, no sentinel.
        // This MUST stay readable -- rejecting it would invalidate stored images.
        const UINT32 legacy = 0x50u | ((UINT32)VBLock_Addr32 << 24);
        TF_CHECK_EQ(VBLock_SyncForm(legacy), VBLockSync_Legacy);
        TF_CHECK_EQ((int)VBLock_SyncAddr(legacy), (int)VBLock_Addr32);
    }

    TF_CASE("the historic complement check cannot see a byte swap")
    {
        // The regression this sentinel exists for: complement is per-bit and byte
        // swap is a bit permutation, so they commute and the pair survives intact.
        const UINT32 w  = VBLock_SyncMake ( 0x50, VBLock_Addr32 );
        const UINT32 c  = ~w;
        const UINT32 sw = tf_bswap32 ( w );
        const UINT32 sc = tf_bswap32 ( c );
        TF_CHECK((sw & sc) == 0u && (sw | sc) == ~0u);   // old test: passes
        TF_CHECK_EQ(VBLock_SyncForm(sw), VBLockSync_Swapped);   // new test: caught
    }

    TF_CASE("P2Piomage_Alloc emits the sentinel and round-trips its size")
    {
        const char data[] = "endian";
        P2Piomage *pIOmage = P2Piomage_Alloc ( data, (UINT32)sizeof(data) );
        TF_CHECK(pIOmage != nullptr);
        if ( pIOmage )
        {
          TF_CHECK_EQ(VBLock_SyncForm(pIOmage->oSync.uiSync1), VBLockSync_Native);
          TF_CHECK_EQ((int)VBLock_SyncAddr(pIOmage->oSync.uiSync1), (int)VBLock_Addr32);
          TF_CHECK_EQ((int)P2Piomage_Sizeof(pIOmage),
                      (int)(sizeof(VBListIOmage) + sizeof(data)));
          TF_CHECK((pIOmage->oSync.uiSync1 + pIOmage->oSync.uiSync2) == ~0u);
          P2Piomage_Release ( pIOmage );
        }
    }

    TF_CASE("a foreign-endian image is rejected instead of returning a bogus size")
    {
        const char data[] = "endian";
        P2Piomage *pIOmage = P2Piomage_Alloc ( data, (UINT32)sizeof(data) );
        TF_CHECK(pIOmage != nullptr);
        if ( pIOmage )
        {
          // Byte-swap the header in place: exactly what a big-endian peer's image
          // looks like to this host.
          pIOmage->oSync.uiSync1 = tf_bswap32 ( pIOmage->oSync.uiSync1 );
          pIOmage->oSync.uiSync2 = tf_bswap32 ( pIOmage->oSync.uiSync2 );

          bool bRejected = false;
          try { P2Piomage_Sizeof ( pIOmage ); }
          catch ( P2Pevent* pEVT ) { if ( pEVT ) pEVT->Cancel(false); bRejected = true; }
          TF_CHECK(bRejected);

          P2Piomage_Release ( pIOmage );   // frees the buffer; does not read oSync
        }
    }
}

// ---------------------------------------------------------------------------
// LAYOUT GENERATION (VERSIONING.md §6, gate 2).
// The six sentinel bits are the message image's only version story. ONE code
// is defined - the one this build writes - and every OTHER non-zero pattern
// classifies as VBLockSync_Gen, "a layout this build does not implement".
// These cases exist because that fallback replaced an enumerated registry of
// reserved codes, and the two differ in exactly the four places tested below:
// what a FUTURE generation reports as, where VBLockSync_Invalid now comes
// from, what the byte-order diagnosis costs, and what the fallback gives up.
static UINT32 tf_syncword ( UINT32 uGenBits, UINT32 nSize, UINT08 uAddr )
{
    return (nSize & 0x00FFFFFFu)
         | ( ( uGenBits | (UINT32)(uAddr & VBLock_AddrMask) ) << 24 );
}

static void Test_IOmageLayoutGeneration()
{
    TF_CASE("the generation costs the format nothing - the word is unchanged")
    {
        // THE POINT OF THE WHOLE MECHANISM, as a literal. If promoting the
        // sentinel to a generation tag had moved one bit of what this build
        // writes, it would be a wire break; this is the constant that says it
        // did not. 0x50 bytes, Addr32 (2), generation 1 (0xA4) -> 0xA6000050.
        TF_CHECK_EQ((int)VBLock_SyncMake ( 0x50, VBLock_Addr32 ), (int)0xA6000050u);
        TF_CHECK_EQ((int)VBLock_SyncGenNow, (int)VBLock_SyncGen1);
        TF_CHECK_EQ((int)sizeof(VBListIOmage::oSync), 8);
    }

    TF_CASE("EVERY layout this build does not implement is named, not called corrupt")
    {
        // The case an enumerated registry could not make. It named the ONE
        // reserved code somebody had thought to declare and reported every
        // other as an unrecognised image, so it bought a diagnostic for
        // generation 2 and said nothing about generation 3. The fallback names
        // all 62 free codes, including the ones nobody has designed yet.
        static const UINT32 aCodes[] = { 0xA8, 0xAC, 0xB0, 0x04, 0xF8, 0xFC };
        for ( size_t i = 0; i < sizeof(aCodes)/sizeof(aCodes[0]); ++i )
        {
          const UINT32 w = tf_syncword ( aCodes[i], 0x50, VBLock_Addr32 );
          TF_CHECK_EQ(VBLock_SyncForm(w), VBLockSync_Gen);
          TF_CHECK_EQ((int)VBLock_SyncGenCode(w), (int)aCodes[i]);
          TF_CHECK_EQ((int)VBLock_SyncAddr(w), (int)VBLock_Addr32);
        }
    }

    TF_CASE("the classifier classifies EVERYTHING - Invalid is the complement gate's word")
    {
        // VBLock_SyncForm returns Gen as its fallback, so VBLockSync_Invalid
        // cannot come out of it any more. Swept over all 64 codes rather than
        // asserted of the two that happen to be interesting.
        for ( UINT32 uCode = 0; uCode < 64; ++uCode )
        {
          const UINT32 w = tf_syncword ( uCode << 2, 0x50, VBLock_Addr32 );
          TF_CHECK(VBLock_SyncForm(w) != VBLockSync_Invalid);
        }

        // And that is not a hole, which is the half this checks: the complement
        // pair is the structural filter, it runs BEFORE the classifier, and it
        // still refuses. A word reaches the classifier only by already being a
        // valid pair - which random bytes manage 2^-32 of the time.
        const char data[] = "complement";
        P2Piomage *pIOmage = P2Piomage_Alloc ( data, (UINT32)sizeof(data) );
        TF_CHECK(pIOmage != nullptr);
        if ( pIOmage )
        {
          pIOmage->oSync.uiSync2 ^= 1u;      // one bit off the complement
          bool bRejected = false;
          try { P2Piomage_Sizeof ( pIOmage ); }
          catch ( P2Pevent* pEVT ) { if ( pEVT ) pEVT->Cancel(false); bRejected = true; }
          TF_CHECK(bRejected);

          P2Piomage_Release ( pIOmage );     // frees the buffer; does not read oSync
        }
    }

    TF_CASE("a swapped image of THIS generation is still a swap")
    {
        // The arm the sentinel existed for in the first place, unchanged.
        const UINT32 mine = VBLock_SyncMake ( 0x50, VBLock_Addr32 );
        TF_CHECK_EQ(VBLock_SyncForm(tf_bswap32(mine)), VBLockSync_Swapped);
    }

    TF_CASE("the 1/64 the registry was spending is back - byte_order.md 4.4")
    {
        // Under the enumerated registry a swapped image whose size low byte
        // fell in 0xA8-0xAB was taken by the Gen arm before the swap arm could
        // see it: the third miss range, and the whole standing price of
        // reserving a code. 0x0000A8 bytes, swapped, is that exact image and
        // it is diagnosed correctly now. The miss set is two ranges again.
        const UINT32 mine = VBLock_SyncMake ( 0x0000A8, VBLock_Addr32 );
        TF_CHECK_EQ(VBLock_SyncForm(tf_bswap32(mine)), VBLockSync_Swapped);
    }

    TF_CASE("a swapped FUTURE generation reports as a generation - the residual")
    {
        // The honest cost of the fallback, pinned so it stays a known residual
        // rather than a surprise. The swap arm looks for a code THIS build
        // would have written, so a big-endian peer running generation 3 is
        // refused as an unimplemented layout rather than as an endianness
        // mismatch. Cross-endian AND cross-generation at once - and the
        // registry covered it for exactly one code, at 1/64 of the diagnosis.
        const UINT32 future = tf_syncword ( 0xB0, 0x50, VBLock_Addr32 );
        TF_CHECK_EQ(VBLock_SyncForm(tf_bswap32(future)), VBLockSync_Gen);
    }

    TF_CASE("the fallback is LAST - it swallows nothing the arms above it own")
    {
        // Ordering guard. Gen is the default return, so any arm placed after
        // it would be dead and any arm it displaced would be silently lost.
        const UINT32 mine = VBLock_SyncMake ( 0x50, VBLock_Addr32 );
        TF_CHECK_EQ(VBLock_SyncForm(mine), VBLockSync_Native);
        TF_CHECK_EQ(VBLock_SyncForm(tf_syncword ( 0, 0x50, VBLock_Addr32 )),
                    VBLockSync_Legacy);
        TF_CHECK(VBLock_SyncIsGen ( VBLock_SyncGenNow ) != 0);
        TF_CHECK(VBLock_SyncIsGen ( 0xB0 ) == 0);
    }
}

// ---------------------------------------------------------------------------
// An item's uItemType is WIRE data. The VBLockItem_p* resolvers recognise four
// of the sixteen values the type field can hold; the other twelve used to fall
// through an ASSERT(0) to `return 0`, and ASSERT is compiled out of Release.
// None of the seventeen call sites tests the result -- P2PmsgObject_pData hands
// it straight to VBLockData_IsChained, which dereferences it. A peer that set
// an item type this build does not know therefore faulted inside
// P2Peerio::RecvP2PeerMsg rather than having its frame refused.
//
// p2p_fuzzframe covers this on the wire path (case 0 iteration 36), but only on
// Windows: its assert trap is _CrtSetReportHook, so on glibc the harness aborts
// at the first ASSERT and never reaches iteration 36. These cases call the
// resolvers directly so the guard is checked on BOTH platforms.
static void Test_VBLockItem_UnknownType()
{
    // Addr32, Alloc|Linked -- the header byte the fuzzer's item block carried.
    const UCHAR uVBLock = VBLock_Addr32 | VBLock_Item | VBLock_Alloc | VBLock_Linked;

    auto rejects = []( auto fn ) -> bool {
        try { fn(); return false; }
        catch ( P2Pevent* pEVT ) { if ( pEVT ) pEVT->Cancel(false); return true; }
    };

    TF_CASE("an unknown VBLockItem type is refused, not resolved to NULL")
    {
        // VBLock_Root is a real type constant but not one of the four an item
        // may be (Field/Data/List/Vect), so every resolver falls through.
        VBLockItem oItem;
        std::memset ( &oItem, 0, sizeof(oItem) );
        oItem.uItemType = VBLock_Root;

        TF_CHECK(rejects([&]{ VBLockItem_pData  ( uVBLock, &oItem ); }));
        TF_CHECK(rejects([&]{ VBLockItem_pField ( uVBLock, &oItem ); }));
        TF_CHECK(rejects([&]{ VBLockItem_pName  ( uVBLock, &oItem ); }));
    }

    TF_CASE("a null VBLockItem is refused, not resolved to NULL")
    {
        // Every VBLockItem_Is* predicate answers false for NULL, so a null item
        // reaches the same fall-through. It arrives when an address does not
        // resolve in the image.
        TF_CHECK(rejects([&]{ VBLockItem_pData  ( uVBLock, nullptr ); }));
        TF_CHECK(rejects([&]{ VBLockItem_pField ( uVBLock, nullptr ); }));
        TF_CHECK(rejects([&]{ VBLockItem_pName  ( uVBLock, nullptr ); }));
    }
}

// ---------------------------------------------------------------------------
void RunMsgcoreSuite()
{
    Test_Data_TypedValues();
    Test_Data_CopySemantics();
    Test_Time();
    Test_HeapWidths();
    Test_Field_NameAndData();
    Test_List();
    Test_Vect();
    Test_AttrDesc();
    Test_Curs_GotoKeyLifetime();
    Test_VBLockItem_UnknownType();
    Test_Stack();
    Test_Event();
    Test_VariantWideString();
    Test_IOmageEndianSentinel();
    Test_IOmageLayoutGeneration();
}
