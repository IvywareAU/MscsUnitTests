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
#include "MsgFieldRef.hpp"

#include "TestFramework.h"

#include <cmath>
#include <functional>

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

    // The same overrun reached through a FIELD, not a bare name. Until
    // 2026-10-02 this was heap corruption, not an exception: the P3PmsgField
    // constructors alias both bases' m_pObject onto the member m_oObject
    // (RenderThisSafe) before c_name throws, and the base destructors that
    // unwind the half-built field `delete` that member address. MSVC Debug
    // reported it as _CrtIsValidHeapPointer -- which this runner's assert hook
    // folds into a FAILED CHECK, so these cases fail loudly if it comes back.
    TF_CASE("a field built with a 64-unit name throws cleanly; the unwind frees nothing it does not own")
    {
        auto throws = []( auto fn ) -> bool {
            try { fn(); return false; }
            catch ( P2Pevent* pEVT ) { if ( pEVT ) pEVT->Cancel(false); return true; }
        };
        const std::wstring n64(64, L'n');
        TF_CHECK(throws([&]{ P3PmsgField f( n64.c_str(), P3PmsgData((int)1) ); }));
        TF_CHECK(throws([&]{ P3PmsgField f( n64.c_str(), (size_t)0 ); }));

        // And through DeclareItem, which is how it was found: the parent is
        // left exactly as it was, and still usable.
        P3PmsgField oRoot(L"Root");
        oRoot.DeclareItem(L"kept", P3PmsgData((int)7));
        TF_CHECK(throws([&]{ oRoot.DeclareItem(n64.c_str(), P3PmsgData((int)1)); }));
        TF_CHECK(oRoot.SelectItem(L"kept").c_int() == 7);
        oRoot.DeclareItem(L"after", P3PmsgData((int)8));
        TF_CHECK(oRoot.SelectItem(L"after").c_int() == 8);
    }

    // A path COMPONENT longer than any name. ParseObjectPath copied it into a
    // MAX_TNAME_SIZE stack array with only an ASSERT(0) on overrun, so at 64
    // units the array was left unterminated (ASan, Linux: a 260-byte read out
    // of P3Pmsg_SelectObjectRecurse's frame) and past that it was written off
    // the end -- in Release, where the ASSERT is compiled out. Paths are caller
    // data (RootPath2Object answers queries from across the mesh), so the
    // answer is "no such object", which is what a name that matches nothing
    // already gets.
    TF_CASE("a path component longer than any name selects nothing and overruns nothing")
    {
        P3PmsgField oRoot(L"Root");
        oRoot.DeclareItem(L"a", P3PmsgData((int)1));
        oRoot.SelectItem(L"a").DeclareItem(L"b", P3PmsgData((int)2));
        for ( size_t n : { (size_t)63, (size_t)64, (size_t)65, (size_t)1000 } )
        {
            const std::wstring big(n, L'z');
            TF_CHECK(!oRoot.Exists(big.c_str()));
            TF_CHECK(oRoot.SelectObject(big.c_str()).IsVoid());
            TF_CHECK(oRoot.SelectObject((L"a." + big).c_str()).IsVoid());
            TF_CHECK(oRoot.SelectObject((L"." + big).c_str()).IsVoid());
            TF_CHECK(oRoot.SelectObject((big + L".b").c_str()).IsVoid());
        }
        // The ordinary path still resolves, so the guard refused only the overlong.
        TF_CHECK(!oRoot.SelectObject(L"a.b").IsVoid());
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
        oItem.r_name() = L"TestNodeName";
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
        oItem.r_name() = L"GotoKeyLifetime";
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
        oItem.r_name() = L"RenameKeyLifetime";
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
        oNewName.r_name() = L"Renamed";
        LPCTNAM lpszNew = oNewName.r_name().c_name();

        P3PmsgRefactor_Rename ( oItem, lpszOld, lpszNew );

        TF_CHECK(oItem.r_Desc().Exists(L"Renamed"));
        TF_CHECK(!oItem.r_Desc().Exists(L"Item23"));
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
        oItem.r_name() = L"FindChildKeyLifetime";
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        for ( int i = 0; i < kItems; i++ )
        {
          wchar_t szName[32];
          swprintf_s(szName, 32, L"Item%02d", i);
          P3PmsgField oChild(szName);
          if ( i == kItems - 1 )
            oChild.r_Attr(P3PmsgField::AttrCMD_Create) += P3PmsgField(L"Marked");
          oItem.r_Desc() += oChild;
        }

        //  Both keys are bare c_name() pointers - live ring slots, not copies.
        P3PmsgCurs oCursKey(oItem.r_Desc());
        TF_CHECK(oCursKey.Goto(kItems - 1));
        LPCTNAM lpszChild = oCursKey.r_name().c_name();

        P3PmsgItem oAttrName;
        oAttrName.r_name() = L"Marked";
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
        oItem.r_name() = L"FindChildSense";
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        for ( int i = 0; i < 4; i++ )
        {
          wchar_t szName[32];
          swprintf_s(szName, 32, L"Kid%d", i);
          P3PmsgField oChild(szName);
          if ( i == 2 )
            oChild.r_Attr(P3PmsgField::AttrCMD_Create) += P3PmsgField(L"Tag");
          oItem.r_Desc() += oChild;
        }

        P3PmsgObject oHit = P3Pmsg_FindChildWithAttr ( oItem, L"Tag", L"Kid2" );
        TF_CHECK(!oHit.IsVoid());
        if (!oHit.IsVoid())
        {
          P3PmsgField oHitField = oHit;
          TF_CHECK(oHitField == L"Kid2");
        }

        //  A wildcard that matches the marked child.
        P3PmsgObject oWild = P3Pmsg_FindChildWithAttr ( oItem, L"Tag", L"Kid*" );
        TF_CHECK(!oWild.IsVoid());

        //  No name given at all - the documented default - still finds it.
        P3PmsgObject oAny = P3Pmsg_FindChildWithAttr ( oItem, L"Tag" );
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
        oItem.r_name() = L"FindChildMiss";
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        for ( int i = 0; i < 4; i++ )
        {
          wchar_t szName[32];
          swprintf_s(szName, 32, L"Kid%d", i);
          P3PmsgField oChild(szName);
          if ( i == 2 )
            oChild.r_Attr(P3PmsgField::AttrCMD_Create) += P3PmsgField(L"Tag");
          oItem.r_Desc() += oChild;      // all four are LEAVES - no r_Desc()
        }

        P3PmsgObject oNoName  = P3Pmsg_FindChildWithAttr ( oItem, L"Tag",        L"Nobody" );
        P3PmsgObject oNoAttr  = P3Pmsg_FindChildWithAttr ( oItem, L"NoSuchAttr", L"Kid1"   );
        P3PmsgObject oNeither = P3Pmsg_FindChildWithAttr ( oItem, L"NoSuchAttr", L"Nobody" );
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
        oItem.r_name() = L"ExistsHost";
        oItem.r_Desc(P3PmsgField::AttrCMD_Create);
        oItem.r_Desc() += P3PmsgField(L"Present");

        TF_CHECK(oItem.r_Desc().Exists(L"Present"));
        TF_CHECK(!oItem.r_Desc().Exists(L"Absent"));

        //  And through the field-level overload, which is the one most callers
        //  reach for.
        TF_CHECK(oItem.Exists(L"Present"));
        TF_CHECK(!oItem.Exists(L"Absent"));
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
        //  It truncates on Windows too. An L"..." literal selects the wide
        //  overload,
        //  where p2p_fix_wformat maps %s to %ls for glibc and MSVC takes it
        //  natively; a genuinely narrow argument such as __FUNCTION__ is %hs
        //  there, whose 'h' p2p_fix_wformat erases for the same reason.
        P2Pevent* pEVT = EVERR->Message(L"addr=[%s] fn=[%hs]",
                                        L"Alpha.Bravo", "TheFunction");
        TF_CHECK(pEVT != nullptr);
        if ( pEVT )
        {
          const CString strMsg = pEVT->GetMessage();
          TF_CHECK(strMsg.Find(L"Alpha.Bravo") >= 0);   // not just "A"
          TF_CHECK(strMsg.Find(L"TheFunction") >= 0);   // narrow arg, via %hs
          TF_CHECK(strMsg.Find(L"%s")          <  0);   // nothing left unconsumed
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
// Field access by name -- MsgFieldRef.hpp (MsgFieldAccessPlan.md, F0-F2)
//
// F0 pins the three Msgcore behaviours the proxy is built on. They were open
// questions when the plan was written; these are the answers, and if one ever
// changes the proxy's reasoning changes with it.
// ---------------------------------------------------------------------------
namespace {

bool ThrowsP2Pevent ( const std::function<void()>& fn )
{
    try { fn(); return false; }
    catch ( P2Pevent* pEVT ) { if ( pEVT ) pEVT->Cancel(false); return true; }
}

// Every case that reads bytes back wants the same comparison.
bool SameBytes ( const MsgBlob& b, const void* pv, size_t cb )
{
    return b.size() == cb && ( cb == 0 || std::memcmp ( b.data(), pv, cb ) == 0 );
}

struct Telemetry : MsgView
{
    MSG_FIELD ( device,  std::wstring );
    MSG_FIELD ( uptime,  int );
    MSG_FIELD ( serial,  long long );
    MSG_FIELD ( ratio,   double );
    MSG_FIELD ( online,  bool );
    MSG_FIELD ( samples, MsgBlob );
    MSG_FIELD ( backup,  std::wstring );
};

struct Stamped : MsgView
{
    MSG_FIELD ( count, short );
    MSG_FIELD ( when,  MsgTime );
};

struct Money : MsgView
{
    MSG_FIELD ( currency, std::wstring );
    MSG_FIELD ( scale,    int );
};

struct Priced : MsgView
{
    MSG_FIELD ( total, double );
};

struct Limits : MsgView
{
    MSG_FIELD ( low,  int );
    MSG_FIELD ( high, int );
};

// Records what an anchor's hooks were told, for the Child() cases.
struct HookLog
{
    std::vector<std::wstring> admitted;
    std::vector<bool>         leaf;
    std::vector<std::wstring> indexed;
    static void Admit ( void *pv, LPCWSTR n, size_t, bool bLeaf )
    { ((HookLog*)pv)->admitted.push_back ( n ); ((HookLog*)pv)->leaf.push_back ( bLeaf ); }
    static void Index ( void *pv, LPCWSTR n, bool ) { ((HookLog*)pv)->indexed.push_back ( n ); }
};

} // namespace

static void Test_FieldAccess_F0Facts()
{
    TF_CASE("F0: DeclareItem(name, data, TRUE) replaces the tag as well as the value")
    {
        P3PmsgField oRoot(L"Root");
        oRoot.DeclareItem(L"x", P3PmsgData((int)5));
        TF_CHECK_EQ((int)oRoot.SelectItem(L"x").r_data().DataType(), VBLockData_INT32);
        oRoot.DeclareItem(L"x", P3PmsgData(L"text"), TRUE);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"x").r_data().DataType(), VBLockData_WSTR16);
        TF_CHECK(wcscmp(oRoot.SelectItem(L"x").c_wstr(), L"text") == 0);
        oRoot.DeclareItem(L"x", P3PmsgData(2.5), TRUE);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"x").r_data().DataType(), VBLockData_DOUBLE);
        TF_CHECK(oRoot.SelectItem(L"x").c_double() == 2.5);
    }

    TF_CASE("F0: c_size() of a rewritten BLOB16 is the STORED length, not the capacity")
    {
        // Open in C++23_vs_Legacy.md until this. A 5-byte cell rewritten with 3
        // bytes reports 3, so a reader that sizes its copy by c_size() gets
        // exactly what the last writer wrote -- growing and emptying included.
        unsigned char buf[40] = { 1, 2, 3, 4, 5 };
        P3PmsgField oRoot(L"Root");
        oRoot.DeclareItem(L"b", P3PmsgData((const void*)buf, 5, VBLockData_BLOB16));
        TF_CHECK_EQ((int)oRoot.SelectItem(L"b").r_data().c_size(), 5);
        oRoot.DeclareItem(L"b", P3PmsgData((const void*)buf, 3, VBLockData_BLOB16), TRUE);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"b").r_data().c_size(), 3);
        oRoot.DeclareItem(L"b", P3PmsgData((const void*)buf, 40, VBLockData_BLOB16), TRUE);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"b").r_data().c_size(), 40);
        oRoot.DeclareItem(L"b", P3PmsgData((const void*)buf, 0, VBLockData_BLOB16), TRUE);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"b").r_data().c_size(), 0);
        // And a WSTR16's is its UTF-16 bytes WITHOUT a terminator.
        oRoot.DeclareItem(L"w", P3PmsgData(L"abc"));
        TF_CHECK_EQ((int)oRoot.SelectItem(L"w").r_data().c_size(), 6);
    }

    TF_CASE("F0: c_vBlob refuses every scalar tag but not a string tag")
    {
        // Why app fields travel as blobs: TargetFacade reads a field with
        // c_vBlob(), so a typed INT32 is an ABSENT field to a facade receiver,
        // and a WSTR16 comes back without the terminator fieldText() strips.
        P3PmsgField oRoot(L"Root");
        oRoot.DeclareItem(L"i", P3PmsgData((int)7));
        oRoot.DeclareItem(L"d", P3PmsgData(1.0));
        oRoot.DeclareItem(L"w", P3PmsgData(L"abc"));
        TF_CHECK(ThrowsP2Pevent([&]{ (void)oRoot.SelectItem(L"i").c_vBlob(); }));
        TF_CHECK(ThrowsP2Pevent([&]{ (void)oRoot.SelectItem(L"d").c_vBlob(); }));
        TF_CHECK(!ThrowsP2Pevent([&]{ (void)oRoot.SelectItem(L"w").c_vBlob(); }));
    }
}

static void Test_FieldRef_Typed()
{
    TF_CASE("MsgFieldRef: every overload round-trips under its own tag")
    {
        P3PmsgField oRoot(L"Root");
        Field(oRoot, L"i")  = 86400;
        Field(oRoot, L"i0") = -1;
        Field(oRoot, L"l")  = 1234567890123LL;
        Field(oRoot, L"d")  = 2.5;
        Field(oRoot, L"bt") = true;
        Field(oRoot, L"bf") = false;
        Field(oRoot, L"w")  = L"sensor-04";
        Field(oRoot, L"s")  = std::wstring(L"std-string");
        Field(oRoot, L"e")  = L"";
        const unsigned char raw[] = { 0, 1, 2, 0xFF, 0x80 };
        Field(oRoot, L"b")  = MsgBlob(raw, sizeof raw);
        Field(oRoot, L"b0") = MsgBlob();

        TF_CHECK_EQ(Field(oRoot, L"i").AsInt(), 86400);
        TF_CHECK_EQ(Field(oRoot, L"i0").AsInt(), -1);
        TF_CHECK(Field(oRoot, L"l").AsInt64() == 1234567890123LL);
        TF_CHECK(Field(oRoot, L"d").AsReal() == 2.5);
        TF_CHECK(Field(oRoot, L"bt").AsBool() == true);
        TF_CHECK(Field(oRoot, L"bf").AsBool() == false);
        TF_CHECK(Field(oRoot, L"w").AsText() == L"sensor-04");
        TF_CHECK(Field(oRoot, L"s").AsText() == L"std-string");
        TF_CHECK(Field(oRoot, L"e").AsText().empty());
        TF_CHECK(SameBytes(Field(oRoot, L"b").AsBlob(), raw, sizeof raw));
        TF_CHECK(Field(oRoot, L"b0").AsBlob().empty());

        TF_CHECK_EQ((int)Field(oRoot, L"i").DataType(),  VBLockData_INT32);
        TF_CHECK_EQ((int)Field(oRoot, L"l").DataType(),  VBLockData_INT64);
        TF_CHECK_EQ((int)Field(oRoot, L"d").DataType(),  VBLockData_DOUBLE);
        TF_CHECK_EQ((int)Field(oRoot, L"bt").DataType(), VBLockData_BOOL);
        TF_CHECK_EQ((int)Field(oRoot, L"w").DataType(),  VBLockData_WSTR16);
        TF_CHECK_EQ((int)Field(oRoot, L"b").DataType(),  VBLockData_BLOB16);
        // And what was written is what the plain API reads -- the proxy adds
        // no wrapping of its own.
        TF_CHECK_EQ(oRoot.SelectItem(L"i").c_int(), 86400);
        TF_CHECK(wcscmp(oRoot.SelectItem(L"w").c_wstr(), L"sensor-04") == 0);
    }

    TF_CASE("MsgFieldRef: a narrow literal is UTF-8 and is stored as UTF-16")
    {
        // Plan 3.3 #2: one storage form for text, so every reader asks the
        // same way. 2-, 3- and 4-byte sequences; the last is astral and is
        // two UTF-16 units on BOTH platforms.
        P3PmsgField oRoot(L"Root");
        Field(oRoot, L"ascii") = "assign this";
        Field(oRoot, L"multi") = "caf\xC3\xA9 \xE2\x82\xAC";           // cafe-acute, euro
        Field(oRoot, L"astro") = "\xF0\x9F\x9A\x80";                   // U+1F680
        TF_CHECK_EQ((int)Field(oRoot, L"ascii").DataType(), VBLockData_WSTR16);
        TF_CHECK(wcscmp(oRoot.SelectItem(L"ascii").c_wstr(), L"assign this") == 0);
        // Expected values as hex escapes: a BOM-less source is read as ANSI by
        // MSVC, so a literal non-ASCII character here would not be one.
        TF_CHECK(Field(oRoot, L"multi").AsText() == L"caf\x00E9 \x20AC");
        TF_CHECK(Field(oRoot, L"astro").AsText() == L"\U0001F680");
        TF_CHECK_EQ((int)oRoot.SelectItem(L"astro").r_data().c_size(), 4);
        // Malformed input is replaced, not thrown over.
        Field(oRoot, L"bad") = "a\xFF" "b\xC3";
        TF_CHECK(Field(oRoot, L"bad").AsText() == L"a\xFFFD" L"b\xFFFD");
    }

    TF_CASE("MsgFieldRef: a rewrite may change the type, and the old reader then refuses")
    {
        P3PmsgField oRoot(L"Root");
        MsgFieldRef x = Field(oRoot, L"x");
        x = 5;
        TF_CHECK_EQ(x.AsInt(), 5);
        x = L"five";
        TF_CHECK(x.AsText() == L"five");
        TF_CHECK(ThrowsP2Pevent([&]{ (void)x.AsInt(); }));
        TF_CHECK(ThrowsP2Pevent([&]{ (void)x.AsBlob(); }));
        TF_CHECK(ThrowsP2Pevent([&]{ (void)x.AsReal(); }));
    }

    TF_CASE("MsgFieldRef: a missing field is not created by reading it")
    {
        P3PmsgField oRoot(L"Root");
        MsgFieldRef m = Field(oRoot, L"missing");
        TF_CHECK(!m.Exists());
        TF_CHECK(ThrowsP2Pevent([&]{ (void)m.AsInt(); }));
        TF_CHECK(ThrowsP2Pevent([&]{ (void)m.AsText(); }));
        TF_CHECK(!m.Erase());
        TF_CHECK(!oRoot.Exists(L"missing"));
    }

    TF_CASE("MsgFieldRef: Erase removes the field")
    {
        P3PmsgField oRoot(L"Root");
        Field(oRoot, L"a") = 1;
        Field(oRoot, L"b") = 2;
        TF_CHECK(Field(oRoot, L"a").Erase());
        TF_CHECK(!Field(oRoot, L"a").Exists());
        TF_CHECK_EQ(Field(oRoot, L"b").AsInt(), 2);
        Field(oRoot, L"a") = 3;                       // and comes back on a write
        TF_CHECK_EQ(Field(oRoot, L"a").AsInt(), 3);
    }

    TF_CASE("MsgFieldRef: a 64-unit name is refused cleanly, leaf or path")
    {
        // MsgFieldRef::CheckName refuses before the tree is touched. (Msgcore's
        // own throw for this used to corrupt the heap; that is fixed and has
        // its own case in Test_Field_NameAndData.)
        P3PmsgField oRoot(L"Root");
        std::wstring n63(63, L'n'), n64(64, L'n');
        Field(oRoot, n63.c_str()) = 1;
        TF_CHECK_EQ(Field(oRoot, n63.c_str()).AsInt(), 1);
        TF_CHECK(ThrowsP2Pevent([&]{ Field(oRoot, n64.c_str()) = 1; }));
        TF_CHECK(ThrowsP2Pevent([&]{ Field(oRoot, n64.c_str())[L"x"] = 1; }));
        TF_CHECK(!oRoot.Exists(n64.c_str()));
        // 31 astral characters are 62 units and fit; 32 are 64 and do not.
        std::wstring a31, a32;
        for ( int i = 0; i < 31; ++i ) a31 += L"\U0001F680";
        a32 = a31 + L"\U0001F680";
        Field(oRoot, a31.c_str()) = 2;
        TF_CHECK_EQ(Field(oRoot, a31.c_str()).AsInt(), 2);
        TF_CHECK(ThrowsP2Pevent([&]{ Field(oRoot, a32.c_str()) = 2; }));
    }

    TF_CASE("MsgFieldRef: refs hold names, not cursor items, so interleaving is safe")
    {
        // Plan 3.3 #5. Each write below moves the parent's cursor; a ref that
        // had kept SelectItem's answer would now be naming a sibling.
        P3PmsgField oRoot(L"Root");
        MsgFieldRef a = Field(oRoot, L"a");
        MsgFieldRef b = Field(oRoot, L"b");
        MsgFieldRef c = Field(oRoot, L"c");
        a = 1; b = 2; c = 3;
        a = 10;
        TF_CHECK_EQ(a.AsInt(), 10);
        TF_CHECK_EQ(b.AsInt(), 2);
        TF_CHECK_EQ(c.AsInt(), 3);
        TF_CHECK_EQ(b.AsInt() + a.AsInt() + c.AsInt(), 15);
    }

    TF_CASE("MsgFieldRef: blob reads are alignment-safe at every offset")
    {
        // A payload starts wherever the pack(1) walk lands. Names of lengths
        // 1..8 shift it through every residue; on the Linux box under UBSan a
        // read through c_vBlob()'s pointer would report here, and AsBlob does
        // not, because it copies out through c_vBlobCopy.
        P3PmsgField oRoot(L"Root");
        const double vals[] = { 1.5, -2.25, 3.125, 1e300, -0.0, 6.5, 7.75, 8.0 };
        std::wstring name;
        for ( int i = 0; i < 8; ++i )
        {
            name += L'k';
            Field(oRoot, name.c_str()) = MsgBlob(&vals[i], sizeof(double));
        }
        name.clear();
        bool bAll = true;
        for ( int i = 0; i < 8; ++i )
        {
            name += L'k';
            MsgBlob b = Field(oRoot, name.c_str()).AsBlob();
            double d = 0;
            bAll = bAll && b.size() == sizeof d;
            if ( b.size() == sizeof d ) std::memcpy(&d, b.data(), sizeof d);
            bAll = bAll && std::memcmp(&d, &vals[i], sizeof d) == 0;
        }
        TF_CHECK(bAll);
    }
}

static void Test_FieldRef_Bytes()
{
    TF_CASE("MsgFieldRef Bytes coding: every value is a blob of the documented size")
    {
        P3PmsgField oRoot(L"Root");
        MsgFieldAnchor a = MsgFieldAnchor::Of(oRoot, MsgFieldCoding::Bytes);
        Field(a, L"i") = 86400;
        Field(a, L"l") = -5LL;
        Field(a, L"d") = 0.5;
        Field(a, L"t") = true;
        Field(a, L"w") = L"abc";
        Field(a, L"u") = "\xF0\x9F\x9A\x80";
        Field(a, L"e") = L"";

        const wchar_t* const names[] = { L"i", L"l", L"d", L"t", L"w", L"u", L"e" };
        bool bAllBlobs = true;
        for ( auto n : names )
            bAllBlobs = bAllBlobs && Field(a, n).DataType() == VBLockData_BLOB16;
        TF_CHECK(bAllBlobs);

        TF_CHECK_EQ((int)oRoot.SelectItem(L"i").r_data().c_size(), 4);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"l").r_data().c_size(), 8);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"d").r_data().c_size(), 8);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"t").r_data().c_size(), 1);
        // Text carries its terminator -- what SetFieldText writes.
        TF_CHECK_EQ((int)oRoot.SelectItem(L"w").r_data().c_size(), 8);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"u").r_data().c_size(), 6);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"e").r_data().c_size(), 2);
        const unsigned char abcz[] = { 'a', 0, 'b', 0, 'c', 0, 0, 0 };
        TF_CHECK(SameBytes(Field(a, L"w").AsBlob(), abcz, sizeof abcz));
        const INT32 i86400 = 86400;
        TF_CHECK(SameBytes(Field(a, L"i").AsBlob(), &i86400, sizeof i86400));

        TF_CHECK_EQ(Field(a, L"i").AsInt(), 86400);
        TF_CHECK(Field(a, L"l").AsInt64() == -5LL);
        TF_CHECK(Field(a, L"d").AsReal() == 0.5);
        TF_CHECK(Field(a, L"t").AsBool());
        TF_CHECK(Field(a, L"w").AsText() == L"abc");
        TF_CHECK(Field(a, L"u").AsText() == L"\U0001F680");
        TF_CHECK(Field(a, L"e").AsText().empty());
    }

    TF_CASE("MsgFieldRef: readers accept either coding, so a reader never has to know")
    {
        P3PmsgField oRoot(L"Root");
        MsgFieldAnchor typed = MsgFieldAnchor::Of(oRoot);
        MsgFieldAnchor bytes = MsgFieldAnchor::Of(oRoot, MsgFieldCoding::Bytes);
        Field(typed, L"ti") = 7;      Field(bytes, L"bi") = 7;
        Field(typed, L"tw") = L"hi";  Field(bytes, L"bw") = L"hi";
        Field(typed, L"td") = 1.25;   Field(bytes, L"bd") = 1.25;
        TF_CHECK_EQ(Field(bytes, L"ti").AsInt(), 7);
        TF_CHECK_EQ(Field(typed, L"bi").AsInt(), 7);
        TF_CHECK(Field(bytes, L"tw").AsText() == L"hi");
        TF_CHECK(Field(typed, L"bw").AsText() == L"hi");
        TF_CHECK(Field(bytes, L"td").AsReal() == 1.25);
        TF_CHECK(Field(typed, L"bd").AsReal() == 1.25);
        // A blob of the wrong SIZE is not the type: 4 bytes is not a double.
        TF_CHECK(ThrowsP2Pevent([&]{ (void)Field(typed, L"bi").AsReal(); }));
        TF_CHECK(ThrowsP2Pevent([&]{ (void)Field(typed, L"bi").AsBool(); }));
    }
}

static void Test_FieldRef_Paths()
{
    TF_CASE("MsgFieldRef nesting: a write creates the path, a read creates nothing")
    {
        P3PmsgField oRoot(L"Root");
        Field(oRoot, L"pos")[L"x"] = 1.5;
        Field(oRoot, L"pos")[L"y"] = -2.5;
        Field(oRoot, L"pos")[L"meta"][L"frame"] = L"world";
        TF_CHECK(Field(oRoot, L"pos")[L"x"].AsReal() == 1.5);
        TF_CHECK(Field(oRoot, L"pos")[L"y"].AsReal() == -2.5);
        TF_CHECK(Field(oRoot, L"pos")[L"meta"][L"frame"].AsText() == L"world");
        // Through the plain API, to be sure the tree is the obvious one.
        TF_CHECK(oRoot.SelectItem(L"pos").SelectItem(L"x").c_double() == 1.5);

        MsgFieldRef ghost = Field(oRoot, L"ghost")[L"child"];
        TF_CHECK(!ghost.Exists());
        TF_CHECK(ThrowsP2Pevent([&]{ (void)ghost.AsInt(); }));
        TF_CHECK(!oRoot.Exists(L"ghost"));
    }

    TF_CASE("MsgFieldRef nesting: siblings at two depths do not disturb each other")
    {
        P3PmsgField oRoot(L"Root");
        MsgFieldRef px = Field(oRoot, L"p")[L"x"];
        MsgFieldRef qx = Field(oRoot, L"q")[L"x"];
        MsgFieldRef top = Field(oRoot, L"top");
        px = 1; qx = 2; top = 3; px = 4;
        TF_CHECK_EQ(px.AsInt(), 4);
        TF_CHECK_EQ(qx.AsInt(), 2);
        TF_CHECK_EQ(top.AsInt(), 3);
        TF_CHECK(px.Erase());
        TF_CHECK(!px.Exists());
        TF_CHECK_EQ(qx.AsInt(), 2);
    }

    TF_CASE("MsgFieldRef: works on a BSTR root, the item a message hands out")
    {
        P3PmsgBSTR oBstr;
        P3PmsgItem& root = oBstr.r_item(VBLockBSTR_ROOT);
        Field(root, L"a") = 1;
        Field(root, L"b")[L"c"] = L"deep";
        TF_CHECK_EQ(Field(oBstr.r_item(VBLockBSTR_ROOT), L"a").AsInt(), 1);
        TF_CHECK(Field(root, L"b")[L"c"].AsText() == L"deep");
    }

    // MsgFieldAnchor::Child (2026-10-03). Four FieldAccessExamples harnesses
    // each hand-rolled this resolver before it existed, because the obvious
    // MsgViewOf<T>(oRoot.SelectItem(L"x")) binds the parent's CURSOR item.
    TF_CASE("MsgFieldAnchor::Child: a view of a named child creates it on the write, not the read")
    {
        P3PmsgField oRoot(L"Root");
        MsgViewOf<Limits> lim(MsgFieldAnchor::Child(oRoot, L"limits"));
        TF_CHECK(!lim->low.Exists());
        TF_CHECK(!oRoot.Exists(L"limits"));          // the read created nothing
        lim->low = -40;
        lim->high = 85;
        TF_CHECK(oRoot.Exists(L"limits"));
        TF_CHECK_EQ(oRoot.SelectItem(L"limits").SelectItem(L"low").c_int(), -40);
        TF_CHECK_EQ(Field(oRoot, L"limits")[L"high"].AsInt(), 85);
    }

    TF_CASE("MsgFieldAnchor::Child: survives the parent's cursor moving, where SelectItem's item does not")
    {
        P3PmsgField oRoot(L"Root");
        Field(oRoot, L"a")[L"low"] = 1;
        Field(oRoot, L"b")[L"low"] = 2;
        MsgViewOf<Limits> byChild(MsgFieldAnchor::Child(oRoot, L"a"));
        P3PmsgItem& cursor = oRoot.SelectItem(L"a");   // the parent's cursor item
        TF_CHECK(&cursor == &oRoot.SelectItem(L"b"));   // ONE object, now standing on b
        TF_CHECK_EQ(Field(cursor, L"low").AsInt(), 2);  // so the held "a" reads b
        TF_CHECK_EQ((int)byChild->low, 1);              // the anchor finds a by name ...
        // ... and its lookup moved that same cursor back: an anchor protects
        // ITSELF, not a reference someone else is holding.
        TF_CHECK_EQ(Field(cursor, L"low").AsInt(), 1);
    }

    TF_CASE("MsgFieldAnchor::Child: chains, and agrees with [] nesting and Anchor()")
    {
        P3PmsgField oRoot(L"Root");
        MsgFieldAnchor deep = MsgFieldAnchor::Child(MsgFieldAnchor::Child(oRoot, L"x"), L"y");
        Field(deep, L"z") = 7;
        TF_CHECK_EQ(Field(oRoot, L"x")[L"y"][L"z"].AsInt(), 7);
        MsgViewOf<Limits> v(Field(oRoot, L"x")[L"y"].Anchor());
        v->high = 9;
        TF_CHECK_EQ(Field(deep, L"high").AsInt(), 9);
        TF_CHECK(Field(deep, L"z").Erase());
        TF_CHECK(!Field(oRoot, L"x")[L"y"][L"z"].Exists());
        TF_CHECK(Field(oRoot, L"x")[L"y"].Exists());   // erasing a leaf leaves its parents
    }

    TF_CASE("MsgFieldAnchor::Child: keeps the coding, checks every name, and hooks see the first name")
    {
        P3PmsgField oRoot(L"Root");
        MsgViewOf<Limits> wire(MsgFieldAnchor::Child(oRoot, L"lim", MsgFieldCoding::Bytes));
        wire->low = 3;
        TF_CHECK_EQ((int)Field(oRoot, L"lim")[L"low"].DataType(), VBLockData_BLOB16);
        TF_CHECK_EQ((int)wire->low, 3);

        std::wstring n64(64, L'n');
        MsgFieldAnchor bad = MsgFieldAnchor::Child(oRoot, n64.c_str());
        TF_CHECK(ThrowsP2Pevent([&]{ Field(bad, L"v") = 1; }));
        TF_CHECK(!oRoot.Exists(n64.c_str()));

        // A hooked anchor, the shape AppFields() builds: one context for the
        // resolver and both hooks.
        HookLog log;
        struct Ctx { P3PmsgItem* p; HookLog* log; } ctx { &oRoot, &log };
        MsgFieldAnchor hooked;
        hooked.pvCtx      = &ctx;
        hooked.pfnResolve = [](void* pv, bool) -> P3PmsgItem* { return ((Ctx*)pv)->p; };
        hooked.pfnAdmit   = [](void* pv, LPCWSTR n, size_t cb, bool b) { HookLog::Admit(((Ctx*)pv)->log, n, cb, b); };
        hooked.pfnIndex   = [](void* pv, LPCWSTR n, bool b) { HookLog::Index(((Ctx*)pv)->log, n, b); };
        Field(MsgFieldAnchor::Child(hooked, L"grp"), L"leaf") = 1;
        TF_CHECK_EQ((int)log.admitted.size(), 1);
        TF_CHECK(log.admitted.size() == 1 && log.admitted[0] == L"grp" && !log.leaf[0]);
        TF_CHECK(log.indexed.empty());          // the leaf is not directly under the parent
        Field(hooked, L"top") = 2;
        TF_CHECK(log.indexed.size() == 1 && log.indexed[0] == L"top");
    }
}

// short and MsgTime (2026-10-03). Before these, `= (short)7` was promoted to
// INT32 and a TIME64 cell could only be written with DeclareItem(P3PmsgTime)
// and not read at all -- AsInt64 refuses it, by the own-type rule.
static void Test_FieldRef_ShortTime()
{
    TF_CASE("MsgFieldRef short: an exact short stores INT16; promoting types still store INT32")
    {
        P3PmsgField oRoot(L"Root");
        Field(oRoot, L"s") = (short)-7;
        TF_CHECK_EQ((int)Field(oRoot, L"s").DataType(), VBLockData_INT16);
        TF_CHECK_EQ((int)Field(oRoot, L"s").AsShort(), -7);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"s").r_data().c_short(), -7);   // the plain reader agrees
        // A plain P3PmsgData(INT16) cell reads the same way.
        oRoot.DeclareItem(L"plain", P3PmsgData((INT16)300), TRUE);
        TF_CHECK_EQ((int)Field(oRoot, L"plain").AsShort(), 300);

        Field(oRoot, L"c")  = 'A';                     // char promotes to int
        Field(oRoot, L"us") = (unsigned short)9;       // so does unsigned short
        TF_CHECK_EQ((int)Field(oRoot, L"c").DataType(), VBLockData_INT32);
        TF_CHECK_EQ((int)Field(oRoot, L"us").DataType(), VBLockData_INT32);

        // Own type only: AsInt does not widen a short, AsShort does not narrow an int.
        TF_CHECK(ThrowsP2Pevent([&]{ (void)Field(oRoot, L"s").AsInt(); }));
        TF_CHECK(ThrowsP2Pevent([&]{ (void)Field(oRoot, L"c").AsShort(); }));
    }

    TF_CASE("MsgFieldRef MsgTime: stores TIME64, and the plain API and P3PmsgTime agree")
    {
        P3PmsgField oRoot(L"Root");
        const long long t = 1700000000LL;
        Field(oRoot, L"t") = MsgTime(t);
        TF_CHECK_EQ((int)Field(oRoot, L"t").DataType(), VBLockData_TIME64);
        TF_CHECK(Field(oRoot, L"t").AsTime() == MsgTime(t));
        TF_CHECK(oRoot.SelectItem(L"t").r_data().c_time64() == t);        // the plain reader agrees

        // What a long-hand P3PmsgTime wrote, the field layer reads.
        oRoot.DeclareItem(L"plain", P3PmsgTime((__int64)(t + 60)), TRUE);
        TF_CHECK(Field(oRoot, L"plain").AsTime().Seconds() == t + 60);

        // (AsTime also reads TIME32, which c_time() reads, but nothing public
        // CONSTRUCTS a TIME32 cell -- it arrives only in older images -- so
        // there is no way to make one here. A default P3PmsgData has no cell
        // to set: c_time(v) on one faults.)

        // A long long stays an integer; each reader wants its own type.
        Field(oRoot, L"n") = t;
        TF_CHECK_EQ((int)Field(oRoot, L"n").DataType(), VBLockData_INT64);
        TF_CHECK(ThrowsP2Pevent([&]{ (void)Field(oRoot, L"n").AsTime(); }));
        TF_CHECK(ThrowsP2Pevent([&]{ (void)Field(oRoot, L"t").AsInt64(); }));
    }

    TF_CASE("MsgFieldRef short and MsgTime in the Bytes coding: 2 and 8 native bytes")
    {
        P3PmsgField oRoot(L"Root");
        MsgFieldAnchor bytes = MsgFieldAnchor::Of(oRoot, MsgFieldCoding::Bytes);
        Field(bytes, L"s") = (short)513;
        Field(bytes, L"t") = MsgTime(42);
        TF_CHECK_EQ((int)Field(bytes, L"s").DataType(), VBLockData_BLOB16);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"s").r_data().c_size(), 2);
        TF_CHECK_EQ((int)oRoot.SelectItem(L"t").r_data().c_size(), 8);
        TF_CHECK_EQ((int)Field(oRoot, L"s").AsShort(), 513);              // a Typed reader
        TF_CHECK(Field(oRoot, L"t").AsTime() == MsgTime(42));
        // On the wire a time IS 8 bytes: the int64 reader takes it, by design.
        TF_CHECK(Field(oRoot, L"t").AsInt64() == 42);
        TF_CHECK(ThrowsP2Pevent([&]{ (void)Field(oRoot, L"s").AsInt(); }));  // 2 bytes is not 4
    }

    TF_CASE("MSG_FIELD short and MsgTime: msg->count, msg->when, in both codings")
    {
        for (int coding = 0; coding < 2; ++coding)
        {
            P3PmsgField oRoot(L"Root");
            MsgViewOf<Stamped> msg(oRoot, coding ? MsgFieldCoding::Bytes : MsgFieldCoding::Typed);
            msg->count = (short)12;
            msg->when  = MsgTime(1700000000LL);
            short     n = msg->count;
            MsgTime   w = msg->when;
            TF_CHECK_EQ((int)n, 12);
            TF_CHECK(w.Seconds() == 1700000000LL);
            msg->count = 'x';                           // a char is short-sized, so accepted
            TF_CHECK_EQ((int)msg->count.Get(), (int)'x');
        }
    }
}

// Attributes (2026-10-03): the second set of named children beside the
// descendants, P3PmsgField::r_Attr(). Before this the field layer could not
// reach them -- P3PmsgAttr is not a P3PmsgItem -- so DataFieldTest kept them
// long-hand. Measured first: Exists() on an item with no attribute set is
// false and creates nothing; Create is idempotent; the set follows a cursor
// item; and its operator bool does NOT, so the layer never asks it.
static void Test_FieldRef_Attrs()
{
    TF_CASE("MsgFieldRef::Attr: an attribute is r_Attr()'s, not a descendant, and reads create nothing")
    {
        P3PmsgField oRoot(L"Root");
        Field(oRoot, L"total") = 12.5;
        TF_CHECK(!Field(oRoot, L"total").Attr(L"currency").Exists());
        TF_CHECK(!oRoot.SelectItem(L"total").r_Attr().Exists(L"currency"));   // the read made no set
        Field(oRoot, L"total").Attr(L"currency") = L"AUD";
        TF_CHECK(Field(oRoot, L"total").Attr(L"currency").AsText() == L"AUD");
        TF_CHECK(wcscmp(oRoot.SelectItem(L"total").r_Attr().SelectItem(L"currency").c_wstr(), L"AUD") == 0);
        TF_CHECK(!Field(oRoot, L"total")[L"currency"].Exists());               // not a descendant
        TF_CHECK(Field(oRoot, L"total").AsReal() == 12.5);                    // the field's own value untouched
        TF_CHECK(ThrowsP2Pevent([&]{ (void)Field(oRoot, L"total").Attr(L"absent").AsText(); }));
        TF_CHECK(ThrowsP2Pevent([&]{ (void)Field(oRoot, L"total").Attr(L"currency").AsInt(); }));
    }

    TF_CASE("MsgFieldRef::Attr: a write creates the field and its attribute set; Erase removes one")
    {
        P3PmsgField oRoot(L"Root");
        Field(oRoot, L"order").Attr(L"id") = 42;           // no "order" yet
        TF_CHECK(oRoot.Exists(L"order"));
        TF_CHECK_EQ(Field(oRoot, L"order").Attr(L"id").AsInt(), 42);
        Field(oRoot, L"order").Attr(L"id") = L"A-42";      // a rewrite retypes, as for any field
        TF_CHECK_EQ((int)Field(oRoot, L"order").Attr(L"id").DataType(), VBLockData_WSTR16);
        Field(oRoot, L"order").Attr(L"meta")[L"by"] = L"clerk";   // under an attribute: descendants
        TF_CHECK(oRoot.SelectItem(L"order").r_Attr().SelectItem(L"meta").SelectItem(L"by").r_data().DataType() == VBLockData_WSTR16);
        TF_CHECK(Field(oRoot, L"order").Attr(L"meta").Erase());
        TF_CHECK(!Field(oRoot, L"order").Attr(L"meta").Exists());
        TF_CHECK(Field(oRoot, L"order").Attr(L"id").Exists());   // its sibling stays
        TF_CHECK(!Field(oRoot, L"order").Attr(L"meta").Erase()); // false when it was not there
    }

    TF_CASE("MsgFieldRef::Attr: siblings' attributes stay apart through the shared cursor")
    {
        P3PmsgField oRoot(L"Root");
        MsgFieldRef ax = Field(oRoot, L"a").Attr(L"x");
        MsgFieldRef bx = Field(oRoot, L"b").Attr(L"x");
        ax = 1; bx = 2; ax = 3;
        TF_CHECK_EQ(ax.AsInt(), 3);
        TF_CHECK_EQ(bx.AsInt(), 2);
        TF_CHECK_EQ(oRoot.SelectItem(L"b").r_Attr().SelectItem(L"x").c_int(), 2);
    }

    TF_CASE("MsgFieldAnchor::Attrs: a typed view of an item's attributes; msg->f.Attr and msg.Attr")
    {
        P3PmsgField oRoot(L"Root");
        MsgViewOf<Priced> msg(oRoot);
        msg->total = 99.0;
        msg->total.Attr(L"currency") = L"EUR";                 // an attribute of one member
        MsgViewOf<Money> money(MsgFieldAnchor::Attrs(MsgFieldAnchor::Child(oRoot, L"total")));
        TF_CHECK(money->currency.Get() == L"EUR");
        money->scale = 2;
        TF_CHECK_EQ(Field(oRoot, L"total").Attr(L"scale").AsInt(), 2);
        msg.Attr(L"schema") = L"v1";                           // an attribute of the view's own item
        TF_CHECK(wcscmp(oRoot.r_Attr().SelectItem(L"schema").c_wstr(), L"v1") == 0);
        MsgViewOf<Money> rootMoney(MsgFieldAnchor::Attrs(oRoot));
        TF_CHECK(!rootMoney->currency.Exists());               // the root has no currency attribute
        TF_CHECK(msg->total.Get() == 99.0);
    }

    TF_CASE("Attrs: Child, Anchor(), the Bytes coding and the name check all carry through")
    {
        P3PmsgField oRoot(L"Root");
        MsgFieldAnchor meta = MsgFieldAnchor::Child(MsgFieldAnchor::Attrs(oRoot), L"meta");
        Field(meta, L"k") = 1;                                  // root.r_Attr()["meta"]["k"]
        TF_CHECK_EQ(Field(oRoot.r_Attr().SelectItem(L"meta"), L"k").AsInt(), 1);
        TF_CHECK_EQ(Field(Field(oRoot, L"x").Attr(L"meta").Anchor(), L"k").Exists() ? 1 : 0, 0);
        TF_CHECK_EQ(Field(MsgFieldAnchor::Attrs(oRoot), L"meta")[L"k"].AsInt(), 1);

        MsgFieldAnchor wire = MsgFieldAnchor::Attrs(oRoot, MsgFieldCoding::Bytes);
        Field(wire, L"n") = 7;
        TF_CHECK_EQ((int)Field(MsgFieldAnchor::Attrs(oRoot), L"n").DataType(), VBLockData_BLOB16);
        TF_CHECK_EQ(Field(MsgFieldAnchor::Attrs(oRoot), L"n").AsInt(), 7);

        std::wstring n64(64, L'n');
        TF_CHECK(ThrowsP2Pevent([&]{ Field(oRoot, L"f").Attr(n64.c_str()) = 1; }));
        TF_CHECK(!oRoot.Exists(L"f"));                          // refused before anything was made
    }
}

static void Test_FieldView()
{
    TF_CASE("MSG_FIELD view: msg->field = value, and reads by conversion")
    {
        P3PmsgField oRoot(L"Root");
        MsgViewOf<Telemetry> msg(oRoot);
        msg->device  = L"sensor-04";
        msg->uptime  = 86400;
        msg->serial  = 9000000000LL;
        msg->ratio   = 0.75;
        msg->online  = true;
        const unsigned char raw[] = { 9, 8, 7 };
        msg->samples = MsgBlob(raw, sizeof raw);

        int          up  = msg->uptime;              // the plan's own example
        std::wstring dev = msg->device;
        TF_CHECK_EQ(up, 86400);
        TF_CHECK(dev == L"sensor-04");
        TF_CHECK(msg->serial.Get() == 9000000000LL);
        TF_CHECK(msg->ratio.Get() == 0.75);
        TF_CHECK(msg->online.Get());
        TF_CHECK(SameBytes(msg->samples.Get(), raw, sizeof raw));
        // The names are the identifiers -- the same field the dynamic form sees.
        TF_CHECK_EQ(Field(oRoot, L"uptime").AsInt(), 86400);
        TF_CHECK(Field(oRoot, L"device").AsText() == L"sensor-04");
    }

    TF_CASE("MSG_FIELD view: members take their type's family and convert within it")
    {
        P3PmsgField oRoot(L"Root");
        MsgViewOf<Telemetry> msg(oRoot);
        msg->uptime = (short)12;          // a narrower integer
        TF_CHECK_EQ((int)msg->uptime, 12);
        msg->serial = 7;                  // an int into a long long
        TF_CHECK(msg->serial.Get() == 7LL);
        TF_CHECK_EQ((int)Field(oRoot, L"serial").DataType(), VBLockData_INT64);
        msg->ratio = 3;                   // an int into a double
        TF_CHECK(msg->ratio.Get() == 3.0);
        msg->device = "utf8 \xE2\x82\xAC"; // a narrow literal into text
        TF_CHECK(msg->device.Get() == L"utf8 \x20AC");
        msg->device = std::wstring(L"wide");
        TF_CHECK(msg->device.Get() == L"wide");
    }

    TF_CASE("MSG_FIELD view: field-to-field assignment copies the value")
    {
        P3PmsgField oRoot(L"Root");
        MsgViewOf<Telemetry> msg(oRoot);
        msg->device = L"primary";
        msg->backup = msg->device;
        msg->device = L"changed";
        TF_CHECK(msg->backup.Get() == L"primary");
        TF_CHECK(msg->device.Get() == L"changed");
    }

    TF_CASE("MSG_FIELD view: Exists, Erase and the dynamic form on the same item")
    {
        P3PmsgField oRoot(L"Root");
        MsgViewOf<Telemetry> msg(oRoot);
        TF_CHECK(!msg->uptime.Exists());
        TF_CHECK(ThrowsP2Pevent([&]{ int v = msg->uptime; (void)v; }));
        msg->uptime = 1;
        TF_CHECK(msg->uptime.Exists());
        msg[L"extra"] = 5;                 // not declared by the view
        TF_CHECK_EQ(msg[L"extra"].AsInt(), 5);
        TF_CHECK_EQ(msg->Ref(L"extra").AsInt(), 5);
        TF_CHECK(msg->uptime.Erase());
        TF_CHECK(!Field(oRoot, L"uptime").Exists());
    }

    TF_CASE("MSG_FIELD view: a Bytes-coded view stores blobs and reads them back")
    {
        P3PmsgField oRoot(L"Root");
        MsgViewOf<Telemetry> msg(oRoot, MsgFieldCoding::Bytes);
        msg->device = L"dev";
        msg->uptime = 42;
        TF_CHECK_EQ((int)Field(oRoot, L"device").DataType(), VBLockData_BLOB16);
        TF_CHECK_EQ((int)Field(oRoot, L"uptime").DataType(), VBLockData_BLOB16);
        TF_CHECK(msg->device.Get() == L"dev");
        TF_CHECK_EQ((int)msg->uptime, 42);
    }

    TF_CASE("MSG_FIELD view: a view that was never bound refuses rather than faulting")
    {
        Telemetry t;
        TF_CHECK(ThrowsP2Pevent([&]{ t.uptime = 1; }));
        TF_CHECK(ThrowsP2Pevent([&]{ (void)t.uptime.Exists(); }));
    }
}

// ---------------------------------------------------------------------------
void RunMsgcoreSuite()
{
    Test_FieldAccess_F0Facts();
    Test_FieldRef_Typed();
    Test_FieldRef_Bytes();
    Test_FieldRef_Paths();
    Test_FieldRef_ShortTime();
    Test_FieldRef_Attrs();
    Test_FieldView();
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
