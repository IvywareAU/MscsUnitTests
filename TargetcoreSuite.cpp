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
// TargetcoreSuite.cpp
//
// Unit tests for the Targetcore networking kernel.
//
// Two layers are covered:
//   1. P2PeerMsg32 value plumbing -- source/destin addressing, priority and
//      payload round-trip -- which needs only the message object, no wire.
//   2. End-to-end dispatch -- two P2PeerHubs in one process exchanging a
//      broadcast purely in memory via PostP2Pmsg(msg, targetHub.GetHubID()),
//      the lightest path that still drives a hub pump and On_P2PeerBCast.
//      (This mirrors _Targetcore_UseExamples\LocalInMemoryTest.)

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "Targetcore_c.h"      // the flat C surface (sink + handle-guard cases below)
#include "P2PCngCrypto.h"      // p2pcng::SelfTest — crypto KATs
#include "P2PIdentityStore.h"  // p2pcng identity storage — DPAPI / allow-list
#include "P2PAuthLogin.h"      // p2pauth login proof — signature over the login
#include "P2Peerio.h"          // the crypto seam — Encrypt/DecryptP2PiomageSwap
#include "P2PeerioGcm.h"       // AES-256-GCM implementation of P2PeerioCrypto
#include "P2PeerSeal.h"        // p2pseal end-to-end payload confidentiality

#ifndef _WIN32
#include <sys/stat.h>          // stat/chmod - off Windows the file MODE is the key protection
#endif

#include "TestFramework.h"

#include <string>
#include <vector>
#include <thread>              // the c_name() race case drives it from two threads
#include <atomic>

using namespace std;

// ---------------------------------------------------------------------------
// P2PeerMsg32 : addressing + payload round-trip (no hub, no transport)
// ---------------------------------------------------------------------------
static void Test_MessageValuePlumbing()
{
    TF_CASE("P2PeerMsg32 round-trips source and destination addresses")
    {
        P2PaddrSTR strSrc = L"Mesh.NodeA";
        P2PaddrSTR strDst = L"Mesh.NodeB";
        const wchar_t szPayload[] = L"payload";
        P2Psize_t    nBytes = (P2Psize_t)sizeof(szPayload);

        P2PeerMsg32 oMsg(strSrc, strDst, P2Pmsg_BCast, szPayload, nBytes);

        TF_CHECK(oMsg.GetSource() != nullptr);
        TF_CHECK(oMsg.GetDestin() != nullptr);
        TF_CHECK(wcscmp(oMsg.GetSource(), strSrc) == 0);
        TF_CHECK(wcscmp(oMsg.GetDestin(), strDst) == 0);
    }

    TF_CASE("P2PeerMsg32 preserves its payload bytes and size")
    {
        P2PaddrSTR strSrc = L"Mesh.NodeA";
        P2PaddrSTR strDst = L"Mesh.NodeB";
        const wchar_t szPayload[] = L"hello-in-memory";
        P2Psize_t    nBytes = (P2Psize_t)sizeof(szPayload);

        P2PeerMsg32 oMsg(strSrc, strDst, P2Pmsg_BCast, szPayload, nBytes);

        TF_CHECK_EQ((int)oMsg.DataSize(), (int)nBytes);
        const char* pData = oMsg.Data();
        TF_CHECK(pData != nullptr);
        if (pData)
            TF_CHECK(memcmp(pData, szPayload, nBytes) == 0);
    }

    TF_CASE("SetSource / SetDestin overwrite the addresses")
    {
        P2PeerMsg32 oMsg(L"old.src", L"old.dst", P2Pmsg_BCast, L"x", (P2Psize_t)sizeof(wchar_t) * 2);
        oMsg.SetSource(L"new.src");
        oMsg.SetDestin(L"new.dst");
        TF_CHECK(wcscmp(oMsg.GetSource(), L"new.src") == 0);
        TF_CHECK(wcscmp(oMsg.GetDestin(), L"new.dst") == 0);
    }

    TF_CASE("priority is stored and read back")
    {
        P2PeerMsg32 oMsg(L"s", L"d", P2Pmsg_BCast, L"x", (P2Psize_t)sizeof(wchar_t) * 2);
        oMsg.SetPriority(42);
        TF_CHECK_EQ((int)oMsg.Priority(), 42);
    }
}

// ---------------------------------------------------------------------------
// P2Paddr::c_name() / c_hopname() — where the built name lives
//
// Both are const accessors that hand back a POINTER, so the text has to outlive
// the call. They used to build it in the object's own m_strHubname through a
// const_cast, which has two consequences this case pins down:
//
//   1. Two results from ONE address alias. The second call overwrites the first,
//      so a caller holding both is reading the same buffer twice. Deterministic,
//      single-threaded, and the first case below fails without the fix.
//   2. Two THREADS reading one address race. The build clears the string and
//      appends a character at a time, so a concurrent reader sees a half-built
//      name — and CString reallocation can free the buffer under it. That is
//      live code: GetP2PmsgHubName() (P2Pwin32.cpp) returns c_name() taken from
//      the process-wide hub record and every pump thread calls it.
//
// The name now goes to a per-thread ring (P2Peer.cpp, P2PaddrNameSlot).
// ---------------------------------------------------------------------------
static void Test_AddrNameAccessors()
{
    TF_CASE("two names read from one P2Paddr do not overwrite each other")
    {
        const P2Paddr oAddr(L"Race.Root.Middle.Leaf");

        //  Held at the same time, exactly as a diagnostic holds them when it
        //  passes several accessors to one Message() call.
        P2PaddrSTR pszLast = oAddr.c_name();        // last hop  -> "Leaf"
        P2PaddrSTR pszHop0 = oAddr.c_hopname(0);    // first hop -> "Race"

        TF_CHECK(pszLast != nullptr && pszHop0 != nullptr);
        TF_CHECK(pszLast != pszHop0);               // one buffer per result
        if (pszLast && pszHop0)
        {
            TF_CHECK(wcscmp(pszLast, L"Leaf") == 0);
            TF_CHECK(wcscmp(pszHop0, L"Race") == 0);
        }
    }

    TF_CASE("c_name() on one shared P2Paddr is correct from several threads")
    {
        //  const, and shared by reference: the const_cast in the old accessor is
        //  what made this a write.
        const P2Paddr    oAddr(L"Race.Root.Middle.Leaf");
        std::atomic<int> nWrong(0);
        std::atomic<int> nNull (0);

        //  4 x 20000 is ~80k reads of one buffer. The old build was
        //  clear-then-append-per-character, so the window is wide and a wrong
        //  read is not a rare interleaving - reverting the fix fails this in
        //  the first few hundred iterations.
        const int kThreads = 4;
        const int kReads   = 20000;

        std::vector<std::thread> vThreads;
        for (int t = 0; t < kThreads; ++t)
            vThreads.push_back(std::thread([&]()
            {
                for (int i = 0; i < kReads; ++i)
                {
                    P2PaddrSTR psz = oAddr.c_name();
                    if (!psz)                          { ++nNull;  continue; }
                    if (wcscmp(psz, L"Leaf") != 0)     { ++nWrong; }
                }
            }));

        for (size_t i = 0; i < vThreads.size(); ++i)
            vThreads[i].join();

        TF_CHECK_EQ(nNull.load(),  0);
        TF_CHECK_EQ(nWrong.load(), 0);
    }
}

// ---------------------------------------------------------------------------
// In-memory two-hub delivery
// ---------------------------------------------------------------------------
namespace {

// A hub that signals a caller-supplied event when it dispatches a broadcast.
class SignallingHub : public P2PeerHub
{
public:
    SignallingHub(P2PaddrSTR strAddr, HANDLE hRecvEvent)
        : P2PeerHub(strAddr)
        , m_hRecvEvent(hRecvEvent)
    {}
    virtual ~SignallingHub() {}

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* /*pMsg*/) override
    {
        if (m_hRecvEvent) SetEvent(m_hRecvEvent);
        return msgHANDLED;
    }
    virtual msgRESULT On_P2PeerUCast(P2PeerMsg* /*pMsg*/) override
    {
        if (m_hRecvEvent) SetEvent(m_hRecvEvent);
        return msgHANDLED;
    }

private:
    HANDLE m_hRecvEvent;   // not owned
};

} // namespace

static void Test_InMemoryTwoHubDelivery()
{
    TF_CASE("two hubs in one process exchange a broadcast in memory")
    {
        static const P2PaddrSTR kAddrA = L"UnitMesh.HubA";
        static const P2PaddrSTR kAddrB = L"UnitMesh.HubB";

        HANDLE hRecvA = CreateEvent(NULL, FALSE, FALSE, NULL);
        HANDLE hRecvB = CreateEvent(NULL, FALSE, FALSE, NULL);

        SignallingHub oHubA(kAddrA, hRecvA);
        SignallingHub oHubB(kAddrB, hRecvB);

        oHubA.RequireAuth ( false );
        HANDLE hThreadA = oHubA.SpawnHub();
        oHubB.RequireAuth ( false );
        HANDLE hThreadB = oHubB.SpawnHub();
        TF_CHECK(hThreadA != NULL);
        TF_CHECK(hThreadB != NULL);

        if (hThreadA && hThreadB)
        {
            // A -> B and B -> A, injected straight onto each target's pump.
            const wchar_t szToB[] = L"Hello HubB";
            const wchar_t szToA[] = L"Hello HubA";

            PostP2Pmsg(new P2PeerMsg32(kAddrA, kAddrB, P2Pmsg_BCast,
                                       szToB, (P2Psize_t)sizeof(szToB)),
                       oHubB.GetHubID());
            PostP2Pmsg(new P2PeerMsg32(kAddrB, kAddrA, P2Pmsg_BCast,
                                       szToA, (P2Psize_t)sizeof(szToA)),
                       oHubA.GetHubID());

            HANDLE hBoth[2] = { hRecvA, hRecvB };
            DWORD  dwResult = WaitForMultipleObjects(2, hBoth, /*bWaitAll*/ TRUE, 5000);
            TF_CHECK(dwResult == WAIT_OBJECT_0);   // both delivered before timeout
        }

        oHubA.CloseHub();
        oHubB.CloseHub();
        if (hThreadA) { WaitForSingleObject(hThreadA, 3000); CloseHandle(hThreadA); }
        if (hThreadB) { WaitForSingleObject(hThreadB, 3000); CloseHandle(hThreadB); }
        CloseHandle(hRecvA);
        CloseHandle(hRecvB);
    }
}

// ---------------------------------------------------------------------------
// The flat C API's receive sink (p2peerhub_set_sink / _u8)
//
// Everything else in Targetcore_c.h is post-only; these cases pin the half that
// closes the loop, and they do it entirely through the C surface -- create,
// register, spawn, post, observe -- because that is the only surface a Panama or
// PHP-extension consumer has. The message is injected onto the hub's own pump
// (p2peerhub_post_msg with destin == the hub's address), the same in-memory path
// Test_InMemoryTwoHubDelivery uses, so no socket is involved.
//
// Restored 2026-08-14 with the ABI itself. These cases were deleted in 2010b5a
// along with Targetcore_c.*, and e8bfd04 brought the ABI back without them --
// see the header comment on Test_CApiHandleGuards below.
// ---------------------------------------------------------------------------
namespace {

struct SinkCaptureW
{
    HANDLE  hEvent = nullptr;
    LONG    nCalls = 0;
    wstring wsSrc, wsDst, wsId;
    string  sData;
};

struct SinkCaptureU8
{
    HANDLE  hEvent = nullptr;
    LONG    nCalls = 0;
    string  sSrc, sDst, sId, sData;
};

// Both sinks run on the HUB PUMP thread. They fill their capture, then signal --
// the event orders those writes before the test thread's reads.
static int SinkProbeW(void* pvCtx, const wchar_t* pszSrc, const wchar_t* pszDst,
                      const wchar_t* pszId, const void* pvData, int64_t nSize)
{
    SinkCaptureW* pCap = (SinkCaptureW*)pvCtx;
    pCap->wsSrc = pszSrc ? pszSrc : L"";
    pCap->wsDst = pszDst ? pszDst : L"";
    pCap->wsId  = pszId  ? pszId  : L"";
    pCap->sData.assign((const char*)pvData, (size_t)(pvData && nSize > 0 ? nSize : 0));
    InterlockedIncrement(&pCap->nCalls);
    if (pCap->hEvent) SetEvent(pCap->hEvent);
    return 1;   // consumed: skip the compiled map, no undeliverable bounce
}

static int SinkProbeU8(void* pvCtx, const char* pszSrc, const char* pszDst,
                       const char* pszId, const void* pvData, int64_t nSize)
{
    SinkCaptureU8* pCap = (SinkCaptureU8*)pvCtx;
    pCap->sSrc = pszSrc ? pszSrc : "";
    pCap->sDst = pszDst ? pszDst : "";
    pCap->sId  = pszId  ? pszId  : "";
    pCap->sData.assign((const char*)pvData, (size_t)(pvData && nSize > 0 ? nSize : 0));
    InterlockedIncrement(&pCap->nCalls);
    if (pCap->hEvent) SetEvent(pCap->hEvent);
    return 1;
}

} // namespace

static void Test_CApiHubSink()
{
    static const wchar_t szPayload[] = L"sink-probe";
    const unsigned short nPayload    = (unsigned short)sizeof(szPayload);

    TF_CASE("p2peerhub_set_sink hands an inbound message to a C callback")
    {
        SinkCaptureW oCap;
        oCap.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

        P2PeerHubHandle hHub = p2peerhub_create(L"UnitMesh.SinkHubW");
        TF_CHECK(hHub != nullptr);
        TF_CHECK_EQ(p2peerhub_set_sink(hHub, SinkProbeW, &oCap), 1);

        // Stage 3 step 8: auth is required by default and an unprovisioned hub
        // will not arm, so this in-process delivery probe says so. It is also
        // the flat-C migration under test - p2peerhub_require_auth exists
        // BECAUSE the default flipped, and without it a C consumer would have
        // had no way through this header to start a hub at all.
        p2peerhub_require_auth(hHub, 0);
        TF_CHECK_EQ(p2peerhub_is_auth_required(hHub), 0);

        void* pvThread = p2peerhub_spawn_hub(hHub);
        TF_CHECK(pvThread != nullptr);
        if (pvThread)
        {
            P2PeerMsgHandle hMsg = p2peermsg_create_full(
                L"UnitMesh.Sender", L"UnitMesh.SinkHubW", L"SinkProbe",
                szPayload, nPayload);
            TF_CHECK(hMsg != nullptr);
            // Ownership passes to the hub; 0 back means posted OK.
            TF_CHECK(p2peerhub_post_msg(hHub, hMsg) == nullptr);

            TF_CHECK(WaitForSingleObject(oCap.hEvent, 5000) == WAIT_OBJECT_0);
            TF_CHECK_EQ((int)oCap.nCalls, 1);
            TF_CHECK(oCap.wsId  == L"SinkProbe");
            TF_CHECK(oCap.wsSrc == L"UnitMesh.Sender");
            // dst is read from the hub, not the message (heap discipline) -- this
            // is the case that proves it still equals the delivered destination.
            // Full address, not the leaf: p2peerhub_get_address returns
            // P2Paddr::c_name() and would say "SinkHubW" here.
            TF_CHECK(oCap.wsDst == L"UnitMesh.SinkHubW");
            TF_CHECK_EQ((int)oCap.sData.size(), (int)nPayload);
            TF_CHECK(oCap.sData.size() == nPayload &&
                     memcmp(oCap.sData.data(), szPayload, nPayload) == 0);
        }

        // Clearing is part of the documented contract (fn = NULL after CloseHub).
        //
        // The WaitForSingleObject here is now BELT AND BRACES, and is kept for
        // what it still proves rather than for what it used to do. CloseHub()
        // joins the thread it spawned since 2026-08-20 (ProductionPlan.md C-4),
        // so this returns immediately - and that IS the assertion: a wait that
        // starts timing out would mean the join was lost. The CloseHandle is
        // not optional and never was. p2peerhub_spawn_hub hands back a handle
        // the caller owns; the hub holds a DUPLICATE for its own join, exactly
        // so that closing this one is not a double close.
        p2peerhub_close_hub(hHub);
        if (pvThread) { WaitForSingleObject((HANDLE)pvThread, 3000); CloseHandle((HANDLE)pvThread); }
        TF_CHECK_EQ(p2peerhub_set_sink(hHub, nullptr, nullptr), 1);
        p2peerhub_destroy(hHub);
        CloseHandle(oCap.hEvent);
    }

    TF_CASE("p2peerhub_set_sink_u8 delivers the same message as UTF-8")
    {
        SinkCaptureU8 oCap;
        oCap.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

        P2PeerHubHandle hHub = p2peerhub_create_u8("UnitMesh.SinkHubU8");
        TF_CHECK(hHub != nullptr);
        TF_CHECK_EQ(p2peerhub_set_sink_u8(hHub, SinkProbeU8, &oCap), 1);

        p2peerhub_require_auth(hHub, 0);   // see the wide case above (step 8)

        void* pvThread = p2peerhub_spawn_hub(hHub);
        TF_CHECK(pvThread != nullptr);
        if (pvThread)
        {
            P2PeerMsgHandle hMsg = p2peermsg_create_full_u8(
                "UnitMesh.Sender", "UnitMesh.SinkHubU8", "SinkProbe",
                szPayload, nPayload);
            TF_CHECK(hMsg != nullptr);
            TF_CHECK(p2peerhub_post_msg(hHub, hMsg) == nullptr);

            TF_CHECK(WaitForSingleObject(oCap.hEvent, 5000) == WAIT_OBJECT_0);
            TF_CHECK_EQ((int)oCap.nCalls, 1);
            TF_CHECK(oCap.sId  == "SinkProbe");
            TF_CHECK(oCap.sSrc == "UnitMesh.Sender");
            TF_CHECK(oCap.sDst == "UnitMesh.SinkHubU8");
            // data stays an opaque payload in both variants -- no transcoding.
            TF_CHECK_EQ((int)oCap.sData.size(), (int)nPayload);
            TF_CHECK(oCap.sData.size() == nPayload &&
                     memcmp(oCap.sData.data(), szPayload, nPayload) == 0);
        }

        p2peerhub_close_hub(hHub);
        if (pvThread) { WaitForSingleObject((HANDLE)pvThread, 3000); CloseHandle((HANDLE)pvThread); }
        p2peerhub_destroy(hHub);
        CloseHandle(oCap.hEvent);
    }
}

// ---------------------------------------------------------------------------
// C-ABI handle validation (SECURITY_REVIEW M1)
//
// P2PAddrHandle, P2PeerMsgHandle, P2PeerConWsaHandle and P2PeerHubHandle are all
// `void*`, so before the handle registry landed every entry point static_cast a
// bare pointer and dereferenced it. Four things went wrong there, and these
// cases drive all four: a pointer this API never issued, one it issued and has
// since freed, one of the WRONG KIND, and a perfectly valid one whose underlying
// call throws a P2Pevent across the extern "C" boundary.
//
// Everything below goes through the flat C surface only. That is deliberate:
// it is the whole of what a Panama or PHP consumer can reach, and therefore the
// whole of what anyone who reaches this boundary can drive.
//
// The wild-pointer arm is the one that matters most. 0x1 is not mapped, so any
// implementation that reads through the handle -- including a magic word inside
// a wrapper struct, the design this registry was chosen over -- faults on it.
// Passing means the refusal was decided without a dereference.
//
// WHY THIS BLOCK EXISTS TWICE IN THE HISTORY. It was written in b4401a4 against
// the 54 entry points of the day, deleted in 2010b5a when Targetcore's flat C
// API was deleted, and restored here on 2026-08-14 -- because e8bfd04 restored
// the ABI (now 74 exported entry points, and the surface MSCS_JavaBindings
// downcalls into) WITHOUT restoring these. For that interval the registry and
// the 54-to-74 catch blocks were guards that nothing on either platform
// executed, while Ahtung_Disaster.md's M1 row went on citing this very block as
// the proof they worked. Deleting a test with the code it covers is correct;
// restoring the code without the test is what turned a closed finding back into
// an unverified claim. If the ABI is ever removed again, remove these with it --
// and if it comes back, so do they.
// ---------------------------------------------------------------------------
static void Test_CApiHandleGuards()
{
    TF_CASE("a pointer this API never issued is refused, not dereferenced")
    {
        int nOnStack = 0;
        P2PAddrHandle hStack = (P2PAddrHandle)&nOnStack;      // readable, not a handle
        P2PAddrHandle hWild  = (P2PAddrHandle)(uintptr_t)0x1; // not mapped at all

        TF_CHECK(p2paddr_c_name(hStack) == nullptr);
        TF_CHECK(p2paddr_c_name(hWild)  == nullptr);
        // 1, not 0: "null" is the conservative reading of a refused address --
        // the one that makes a caller stop rather than carry the bad pointer on.
        TF_CHECK_EQ(p2paddr_is_null(hWild),  1);
        TF_CHECK_EQ(p2paddr_is_empty(hWild), 1);
        TF_CHECK_EQ((int)p2paddr_sizeof(hWild), 0);
        // ...whereas a claimed RELATIONSHIP must never come out of a refusal.
        TF_CHECK_EQ(p2paddr_is_child(hWild, L"Any"), 0);
        TF_CHECK_EQ(p2paddr_is_rable(hWild, L"Any"), 0);

        // The other three families answer in their own return shapes.
        TF_CHECK(p2peermsg_get_source((P2PeerMsgHandle)hWild) == nullptr);
        TF_CHECK(p2peermsg_c_name    ((P2PeerMsgHandle)hWild) == nullptr);
        TF_CHECK(p2peermsg_data      ((P2PeerMsgHandle)hWild) == nullptr);
        TF_CHECK_EQ((int)p2peermsg_data_size((P2PeerMsgHandle)hWild), 0);
        TF_CHECK_EQ((int)p2peermsg_priority ((P2PeerMsgHandle)hWild), 0);
        TF_CHECK_EQ(p2peermsg_is_wrapped    ((P2PeerMsgHandle)hWild), 0);
        TF_CHECK(p2peermsg_response_factory((P2PeerMsgHandle)hWild, L"R", nullptr, 0) == nullptr);
        TF_CHECK_EQ((int)p2peerconwsa_get_mode ((P2PeerConWsaHandle)hWild), 0);
        TF_CHECK_EQ(p2peerconwsa_connect       ((P2PeerConWsaHandle)hWild), 0);
        TF_CHECK_EQ(p2peerconwsa_listen        ((P2PeerConWsaHandle)hWild), 0);
        TF_CHECK_EQ((int)p2peerconwsa_get_state((P2PeerConWsaHandle)hWild, 0xFFFFFFFF), 0);
        TF_CHECK(p2peerconwsa_get_address      ((P2PeerConWsaHandle)hWild) == nullptr);
        TF_CHECK_EQ((int)p2peerhub_get_hub_id((P2PeerHubHandle)hWild), 0);
        TF_CHECK(p2peerhub_get_address       ((P2PeerHubHandle)hWild) == nullptr);
        TF_CHECK(p2peerhub_spawn_hub         ((P2PeerHubHandle)hWild) == nullptr);
        TF_CHECK_EQ(p2peerhub_create_hub     ((P2PeerHubHandle)hWild, L"X", 1), 0);
        TF_CHECK_EQ(p2peerhub_con_exists     ((P2PeerHubHandle)hWild, L"X"), 0);
        TF_CHECK_EQ(p2peerhub_set_sink       ((P2PeerHubHandle)hWild, nullptr, nullptr), 0);
        TF_CHECK_EQ(p2peerhub_set_sink_u8    ((P2PeerHubHandle)hWild, nullptr, nullptr), 0);

        // The void-returning entry points have no answer to inspect, so the
        // assertion is made after them: the registry is intact and a real handle
        // still works, i.e. surviving these did not cost anything.
        p2peermsg_set_source ((P2PeerMsgHandle)hWild, L"x");
        p2peermsg_set_destin ((P2PeerMsgHandle)hWild, L"x");
        p2peerconwsa_close   ((P2PeerConWsaHandle)hWild);
        p2peerhub_close_hub  ((P2PeerHubHandle)hWild);
        p2peerhub_pause_hub  ((P2PeerHubHandle)hWild);
        p2peerhub_wakeup_hub ((P2PeerHubHandle)hWild);
        p2paddr_destroy      (hWild);
        p2paddr_destroy      (hStack);
        p2peermsg_destroy    ((P2PeerMsgHandle)hWild);
        p2peerhub_destroy    ((P2PeerHubHandle)hWild);
        p2peerconwsa_destroy ((P2PeerConWsaHandle)hWild);

        P2PAddrHandle hReal = p2paddr_create_str(L"M1Suite.Real");
        TF_CHECK(hReal != nullptr);
        TF_CHECK(p2paddr_c_name(hReal) != nullptr);
        TF_CHECK_EQ(p2paddr_is_null(hReal), 0);
        p2paddr_destroy(hReal);

        // NULL is the degenerate bogus handle and gets the same answers.
        TF_CHECK(p2paddr_c_name(nullptr) == nullptr);
        TF_CHECK_EQ(p2paddr_is_null(nullptr), 1);
        p2paddr_destroy(nullptr);
    }

    TF_CASE("a destroyed handle is refused, and destroying it twice is a no-op")
    {
        P2PAddrHandle hAddr = p2paddr_create_str(L"M1Suite.Dangle");
        TF_CHECK(hAddr != nullptr);
        TF_CHECK(p2paddr_c_name(hAddr) != nullptr);

        p2paddr_destroy(hAddr);

        // The pointer VALUE is unchanged and still non-NULL -- this is exactly
        // the use-after-free a C caller writes by accident. What changed is that
        // the registry no longer knows it, and nothing below reads through it.
        TF_CHECK(p2paddr_c_name(hAddr) == nullptr);
        TF_CHECK_EQ(p2paddr_is_null(hAddr),  1);
        TF_CHECK_EQ((int)p2paddr_sizeof(hAddr), 0);

        p2paddr_destroy(hAddr);            // the double free, now a no-op
        TF_CHECK(p2paddr_c_name(hAddr) == nullptr);
    }

    TF_CASE("a destroyed message handle is refused by every message accessor")
    {
        P2PeerMsgHandle hMsg = p2peermsg_create_msgid(L"M1Dangle");
        TF_CHECK(hMsg != nullptr);
        TF_CHECK(p2peermsg_c_name(hMsg) != nullptr);

        p2peermsg_destroy(hMsg);

        TF_CHECK(p2peermsg_c_name(hMsg)     == nullptr);
        TF_CHECK(p2peermsg_get_source(hMsg) == nullptr);
        TF_CHECK(p2peermsg_get_destin(hMsg) == nullptr);
        TF_CHECK(p2peermsg_data(hMsg)       == nullptr);
        TF_CHECK_EQ((int)p2peermsg_sizeof(hMsg), 0);
        TF_CHECK(p2peermsg_response_factory(hMsg, L"R", nullptr, 0) == nullptr);
        TF_CHECK(p2peermsg_redirect_factory(hMsg, L"M1Suite.Other") == nullptr);
        p2peermsg_destroy(hMsg);
    }

    TF_CASE("a handle of the wrong type is refused, and the object survives it")
    {
        P2PeerMsgHandle hMsg = p2peermsg_create_msgid(L"M1Type");
        TF_CHECK(hMsg != nullptr);

        // The same bytes, offered to the other three families. All four handle
        // typedefs are void*, so this COMPILES -- which is the hole. Before the
        // registry each of these ran a P2Paddr / P2PeerHub / P2PeerConWsa method
        // over a P2PeerMsg's memory.
        TF_CHECK(p2paddr_c_name((P2PAddrHandle)hMsg) == nullptr);
        TF_CHECK_EQ(p2paddr_is_null((P2PAddrHandle)hMsg), 1);
        TF_CHECK_EQ(p2paddr_is_child((P2PAddrHandle)hMsg, L"A"), 0);
        TF_CHECK_EQ((int)p2peerhub_get_hub_id((P2PeerHubHandle)hMsg), 0);
        TF_CHECK(p2peerhub_get_address((P2PeerHubHandle)hMsg) == nullptr);
        TF_CHECK(p2peerhub_spawn_hub((P2PeerHubHandle)hMsg)   == nullptr);
        TF_CHECK_EQ(p2peerconwsa_connect((P2PeerConWsaHandle)hMsg), 0);
        TF_CHECK_EQ((int)p2peerconwsa_get_mode((P2PeerConWsaHandle)hMsg), 0);

        // A wrong-type DESTROY is the dangerous one: it would run some other
        // class's destructor over a live object. The message must come through
        // all three of these unharmed.
        p2paddr_destroy      ((P2PAddrHandle)hMsg);
        p2peerhub_destroy    ((P2PeerHubHandle)hMsg);
        p2peerconwsa_destroy ((P2PeerConWsaHandle)hMsg);

        const wchar_t* pszName = p2peermsg_c_name(hMsg);
        TF_CHECK(pszName != nullptr);
        TF_CHECK(pszName != nullptr && wcscmp(pszName, L"M1Type") == 0);
        p2peermsg_destroy(hMsg);
    }

    TF_CASE("the registry still says yes to the right type")
    {
        // The mirror of the case above, and the reason it is worth writing: a
        // guard that refuses everything would pass every check so far.
        P2PeerHubHandle hHub = p2peerhub_create(L"M1Suite.TypeHub");
        TF_CHECK(hHub != nullptr);
        TF_CHECK(p2peerhub_get_address(hHub) != nullptr);
        TF_CHECK_EQ(p2peerhub_set_sink(hHub, nullptr, nullptr), 1);

        // ...and it is still not a message or an address.
        TF_CHECK(p2peermsg_c_name((P2PeerMsgHandle)hHub) == nullptr);
        TF_CHECK(p2paddr_c_name((P2PAddrHandle)hHub)     == nullptr);

        p2peerhub_destroy(hHub);
        TF_CHECK(p2peerhub_get_address(hHub) == nullptr);
    }

    TF_CASE("a throw from the kernel is reported, not unwound across the C ABI")
    {
        // Every handle in this case is VALID. A hub that was created but never
        // spawned has pump ID 0, and PostP2Pmsg answers an unknown pump by
        // throwing P2Pevent (P2Pwin32.cpp:4800-4808). This is the half of M1
        // that handle validation alone does not touch: before the catch went on
        // every entry point, a C++ exception unwound out of an extern "C"
        // function and took the process with it.
        static const wchar_t szPayload[] = L"m1-throw";

        P2PeerHubHandle hHub = p2peerhub_create(L"M1Suite.NeverSpawned");
        TF_CHECK(hHub != nullptr);
        P2PeerMsgHandle hMsg = p2peermsg_create_full(
            L"M1Suite.Sender", L"M1Suite.NeverSpawned", L"M1Throw",
            szPayload, (unsigned short)sizeof(szPayload));
        TF_CHECK(hMsg != nullptr);

        // Non-NULL is the header's "not delivered", and the handle comes back.
        TF_CHECK(p2peerhub_post_msg(hHub, hMsg) == hMsg);

        // The failed post still CONSUMED the message -- PostP2Pmsg wraps it in an
        // owning P2PeerMsgSP before its first check -- so the registry forgot it
        // at the call. That is what turns the tidy-up a caller naturally writes
        // after a failure into a no-op instead of a double free.
        TF_CHECK(p2peermsg_c_name(hMsg) == nullptr);
        p2peermsg_destroy(hMsg);

        p2peerhub_destroy(hHub);
    }
}

// ---------------------------------------------------------------------------
// The undeliverable cascade
//
// P2PeerTarget::RouteP2PeerMsg is the framework's undeliverable fallback: it
// manufactures a P2Pmsg_Exception WRAPPING the whole message and posts it back
// with the addresses swapped. The exception goes to the original SOURCE - so if
// that address is also unroutable, the exception is undeliverable in its turn,
// and the same code manufactures another one wrapping IT.
//
// That loop runs on the hub's own pump thread and each lap embeds the previous
// message's entire IOMAGE as a BLOB16, so it grows as it spins. It was watched
// doing exactly this during the p2p_sealhop Linux failure - 2048, 5856, 14713,
// 35890 bytes - and the only thing that ever stopped it was the 64K message
// heap throwing (P2PeerHub.cpp records the sizes at the ring-pointer fix that
// removed the TRIGGER; the loop itself was left uncapped).
//
// The rule that caps it: an exception that cannot be delivered has nobody left
// to tell. Both endpoints have been proven unroutable by then - the first by
// the message, the second by the exception - so a third message is addressed to
// no one by construction. It is dropped and logged instead.
//
// Without the fix this case does not fail by a margin: re-measured with the cap
// disabled, m_nRouted reached 4736 in the 1.5 s below and both checks failed.
//
// What the cascade DOES has changed since session 33, though, and the case is
// worth reading with that in mind. MAX_P2PmsgWrapEmbed now elides the embedded
// body once the wrap passes the bound, so the growth stops on its own: 2040,
// 4875, 9091, 13307, 17523, then a fixed 8280 / 12496 / 16712 cycle that never
// ends. The 64 KB heap throw that used to terminate the loop no longer happens.
// A cascade that killed itself in three laps now spins quietly forever, so the
// cap in RouteP2PeerMsg is doing MORE work than when it was written, not less.
// ---------------------------------------------------------------------------
namespace {

// A hub with no connections at all, so every message it is asked to ROUTE is
// undeliverable by construction. PeekP2PeerMsg is the hook P2PeerHub calls on
// each routed message before it scans for a connection, which makes it an exact
// counter of cascade laps.
class CascadeHub : public P2PeerHub
{
public:
    CascadeHub(P2PaddrSTR strAddr)
        : P2PeerHub(strAddr), m_nRouted(0), m_nMaxSize(0)
    {}
    virtual ~CascadeHub() {}

    virtual msgRESULT PeekP2PeerMsg(P2PeerMsg* pMsg) override
    {
        if (pMsg)
        {
            ++m_nRouted;

            // Measure the IMAGE, not Sizeof().
            // NOTES: P2Psize_t is 32-bit now, so Sizeof() no longer wraps at
            //        64 KB - it used to be an unsigned short and reported a
            //        runaway as a SMALL number (a 66292-byte message measured
            //        756 through it), which made a size bound built on it read
            //        green exactly when the thing it guarded had happened, and
            //        64 KB is where this cascade was heading
            //      : The image is still the right thing to measure. Sizeof()
            //        counts the message's heap footprint; P2PiomageSize() is
            //        the byte count that actually goes on the wire - the same
            //        number MAX_P2PmsgWrapEmbed and P2Peerio::m_dwMaxRecvSize
            //        are compared against
            //      : Preparing the image here is safe and does not copy. With
            //        the full mask PrepareP2Piomage() aliases the message's own
            //        heap block rather than building a replica, and
            //        ReleaseP2Piomage() then only drops that alias. Nothing has
            //        prepared an image by the time a hub peeks at a message it
            //        is about to route, which is what the ASSERT inside
            //        PrepareP2Piomage checks
            UINT nImage = 0;
            try
            {
                pMsg->PrepareP2Piomage(~(DWORD)0);
                nImage = pMsg->P2PiomageSize();
                pMsg->ReleaseP2Piomage();
            }
            catch (...)
            {
                // A message too broken to image is not a size observation, and
                // a measuring hook must not change what the hub does next.
                pMsg->ReleaseP2Piomage();
                nImage = 0;
            }

            UINT nSeen = m_nMaxSize.load();
            while (nImage > nSeen && !m_nMaxSize.compare_exchange_weak(nSeen, nImage))
                ;
        }
        return msgCONTINUE;
    }

    std::atomic<int>  m_nRouted;
    std::atomic<UINT> m_nMaxSize;
};

} // namespace

static void Test_UndeliverableCascade()
{
    TF_CASE("an undeliverable exception does not spawn another one")
    {
        static const P2PaddrSTR kHub = L"Cascade.Hub";

        CascadeHub oHub(kHub);
        oHub.RequireAuth ( false );
        HANDLE     hThread = oHub.SpawnHub();
        TF_CHECK(hThread != NULL);

        if (hThread)
        {
            // Neither address exists and the hub has no connections, so the
            // seed is undeliverable AND so is the exception raised about it.
            const wchar_t szPayload[] = L"cascade seed";
            PostP2Pmsg(new P2PeerMsg32(L"Cascade.Src", L"Cascade.Dst",
                                       P2Pmsg_BCast, szPayload,
                                       (P2Psize_t)sizeof(szPayload)),
                       oHub.GetHubID());

            // Long enough for a runaway to be unmistakable: the observed
            // cascade passed 35 KB in four laps.
            Sleep(1500);

            // The seed, then the one exception about it. Nothing after that.
            // Measured without the fix: 3 laps, and the third one dies inside
            // the allocator - "Attempt to exceed maximum P2PmsgHeap size of
            // 65535 bytes" - so a ~100-byte seed costs the hub 64 KB and an
            // uncontrolled throw on its own pump thread.
            TF_CHECK_EQ(oHub.m_nRouted.load(), 2);

            // ...and no lap wrapped a wrap. The exception carries the seed and
            // the event text, so it is larger than the seed - measured at 4875
            // image bytes, the SAME on both platforms - but nothing carries the
            // exception. (The image is a wire byte count, not a sizeof, so it
            // does not move with wchar_t. That was measured, not assumed.)
            //
            // The bound sits between that and the first lap that would wrap it.
            // Measured with the cap in RouteP2PeerMsg disabled, image bytes per
            // lap: 2040, 4875, 9091, 13307, 17523, then a fixed 8280 / 12496 /
            // 16712 cycle that repeats for as long as the hub lives. So 8192
            // fails on lap 3 - the first amplifying lap - with 68% headroom
            // over what a healthy run actually produces.
            //
            // It used to be 16384, measured through Sizeof(). Two reasons that
            // was weaker than it read. Sizeof() returned a 16-bit P2Psize_t
            // back then, so it wrapped at 64 KB and reported a runaway as a
            // small number - see the hook above; P2Psize_t is 32-bit now, but
            // the image is still the number that matters here. And 16384 clears
            // the cycle's 16712 by so little that it was catching the cascade
            // five laps in, not one.
            TF_CHECK(oHub.m_nMaxSize.load() < 8192);
        }

        oHub.CloseHub();
        if (hThread) { WaitForSingleObject(hThread, 3000); CloseHandle(hThread); }
    }
}

// ---------------------------------------------------------------------------
// p2pcng crypto primitives: HMAC/HKDF/AES-GCM/ECDH/ECDSA known-answer tests.
//
// SelfTest() carries published KATs (RFC 4231, RFC 5869), an OpenSSL-generated
// ECDSA P-256 vector, and the identity-isolation check the peer-authentication
// design rests on. Until now nothing on Windows called it: the only caller is
// crypto_kat, which is registered Linux-only because it compiles the OpenSSL
// backend TU directly. So the Windows backend's KATs existed and never ran.
// This is that gap closed - one line, and the vectors start earning their keep.
static void Test_CryptoSelfTest()
{
    TF_CHECK(p2pcng::SelfTest());
}

// ---------------------------------------------------------------------------
// Identity storage: an EcdsaP256 key that survives a restart.
//
// StoreSelfTest() carries the full battery (round-trip, corruption, truncation,
// version, exclusive create, allow-list). The cases below are the ones worth
// stating out loud at suite level, and the DPAPI one is checked HERE through
// plain Win32 file reads rather than through the store's own reader - the
// question "is the key actually protected on disk" should not be answered by
// the component under test.
static std::string IdTempPath(const char* pszLeaf)
{
    char szDir[MAX_PATH + 1] = { 0 };
    DWORD n = GetTempPathA(MAX_PATH, szDir);
    if (n == 0 || n > MAX_PATH) strcpy_s(szDir, ".\\");
    char szOut[MAX_PATH + 64];
    sprintf_s(szOut, "%sp2pid_suite_%s_%lu.tmp", szDir, pszLeaf,
              (unsigned long)GetCurrentProcessId());
    return std::string(szOut);
}

static bool IdReadRaw(const std::string& sPath, std::vector<unsigned char>& vOut)
{
    HANDLE h = CreateFileA(sPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER li;
    bool bOk = (GetFileSizeEx(h, &li) != FALSE) && li.QuadPart > 0 &&
               li.QuadPart < 1024 * 1024;
    if (bOk)
    {
        vOut.assign((size_t)li.QuadPart, 0);
        DWORD cbRead = 0;
        bOk = (ReadFile(h, vOut.data(), (DWORD)vOut.size(), &cbRead, nullptr) != FALSE) &&
              cbRead == vOut.size();
    }
    CloseHandle(h);
    return bOk;
}

static void Test_IdentityStore()
{
    TF_CASE("the identity store passes its own battery")
    {
        TF_CHECK(p2pcng::StoreSelfTest());
    }

    const std::string sId = IdTempPath("id");
    DeleteFileA(sId.c_str());

    unsigned char pubOrig[p2pcng::kEcdsaPubLen] = { 0 };
    unsigned char privOrig[p2pcng::kEcdsaPrivLen] = { 0 };

    TF_CASE("a saved identity signs as the same peer after being loaded back")
    {
        p2pcng::EcdsaP256 oKey;
        TF_CHECK(oKey.Generate());
        TF_CHECK(oKey.ExportPublic(pubOrig));
        TF_CHECK(oKey.ExportPrivate(privOrig));
        TF_CHECK_EQ(p2pcng::SaveIdentity(sId.c_str(), oKey), p2pcng::IdOk);

        p2pcng::EcdsaP256 oBack;
        TF_CHECK_EQ(p2pcng::LoadIdentity(sId.c_str(), oBack), p2pcng::IdOk);

        const char msg[] = "restart survived";
        unsigned char sig[p2pcng::kEcdsaSigLen];
        TF_CHECK(oBack.Sign((const unsigned char*)msg, sizeof(msg) - 1, sig));

        p2pcng::EcdsaP256 oVerify;
        TF_CHECK(oVerify.ImportPublic(pubOrig));
        TF_CHECK(oVerify.Verify((const unsigned char*)msg, sizeof(msg) - 1, sig));
    }

    TF_CASE("the private scalar is not on disk in the clear (DPAPI machine scope)")
    {
        std::vector<unsigned char> vFile;
        TF_CHECK(IdReadRaw(sId, vFile));
        if (vFile.size() > p2pcng::kIdHeaderLen)
        {
            // Header: protection field at offset 10.
            unsigned int nProtect = (unsigned int)vFile[10] |
                                    ((unsigned int)vFile[11] << 8);
#ifdef _WIN32
            // DPAPI machine scope, and the 32-byte scalar d (privOrig + 64)
            // must appear nowhere in the file.
            TF_CHECK_EQ(nProtect, (unsigned int)p2pcng::IdProtect_DpapiMachine);
            bool bClear = false;
            for (size_t i = 0; i + 32 <= vFile.size(); i++)
                if (memcmp(&vFile[i], privOrig + 64, 32) == 0) { bClear = true; break; }
            TF_CHECK(!bClear);
#else
            // POSIX has no DPAPI, so IdProtect_Default resolves to none+0600 and
            // the scalar IS on disk in the clear - the file MODE is the
            // protection. Asserting the Windows shape here would assert that the
            // port is something it deliberately is not, so this checks what
            // actually has to hold: the container declares its protection
            // honestly, and the mode is 0600 and nothing wider.
            TF_CHECK_EQ(nProtect, (unsigned int)p2pcng::IdProtect_None);
            struct stat stId {};
            TF_CHECK(::stat(sId.c_str(), &stId) == 0);
            TF_CHECK_EQ((unsigned int)(stId.st_mode & 0777), 0600u);
#endif

            // Sanity: the search WOULD find the scalar if it were there - so the
            // check above is a real check and not a tautology.
            std::vector<unsigned char> vPlant = vFile;
            vPlant.insert(vPlant.end(), privOrig + 64, privOrig + 96);
            bool bFound = false;
            for (size_t i = 0; i + 32 <= vPlant.size(); i++)
                if (memcmp(&vPlant[i], privOrig + 64, 32) == 0) { bFound = true; break; }
            TF_CHECK(bFound);
        }
    }

    TF_CASE("a corrupted identity file is refused, not loaded")
    {
        std::vector<unsigned char> vFile;
        TF_CHECK(IdReadRaw(sId, vFile));

        const std::string sBad = IdTempPath("bad");
        vFile[p2pcng::kIdHeaderLen] ^= 0x01;
        HANDLE h = CreateFileA(sBad.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        TF_CHECK(h != INVALID_HANDLE_VALUE);
        if (h != INVALID_HANDLE_VALUE)
        {
            DWORD cbWrote = 0;
            WriteFile(h, vFile.data(), (DWORD)vFile.size(), &cbWrote, nullptr);
            CloseHandle(h);

#ifndef _WIN32
            // The store checks the file MODE before it checks the contents, so
            // off Windows a freshly created 0644 file is refused as too
            // permissive and never reaches the digest - which would make this
            // case pass or fail for the wrong reason. Tighten it first so what
            // is being tested really is the integrity check.
            TF_CHECK(::chmod(sBad.c_str(), S_IRUSR | S_IWUSR) == 0);
#endif
            p2pcng::EcdsaP256 oKey;
            TF_CHECK_EQ(p2pcng::LoadIdentity(sBad.c_str(), oKey),
                        p2pcng::IdErrIntegrity);
        }
        DeleteFileA(sBad.c_str());
    }

    TF_CASE("an allow-list entry round-trips to the public key it was written with")
    {
        const std::string sAllow = IdTempPath("allow");
        DeleteFileA(sAllow.c_str());

        TF_CHECK_EQ(p2pcng::AppendAllowList(sAllow.c_str(), "Suite.Peer", pubOrig),
                    p2pcng::IdOk);

        unsigned char pubFound[p2pcng::kEcdsaPubLen] = { 0 };
        TF_CHECK_EQ(p2pcng::FindAllowed(sAllow.c_str(), "Suite.Peer", pubFound),
                    p2pcng::IdOk);
        // memcmp, not p2pcng::ConstTimeEqual: a public key is public, and the
        // comparison primitive stays inside the DLL where the secrets are.
        TF_CHECK(memcmp(pubFound, pubOrig, p2pcng::kEcdsaPubLen) == 0);
        TF_CHECK_EQ(p2pcng::FindAllowed(sAllow.c_str(), "Suite.Stranger", pubFound),
                    p2pcng::IdErrNotFound);

        DeleteFileA(sAllow.c_str());
    }

    DeleteFileA(sId.c_str());
}

// ---------------------------------------------------------------------------
// Login authentication (p2pauth). AuthSelfTest() carries the protocol battery -
// transcript, both blocks, and every refusal path. What is added here is the
// part the self-test cannot reach: the HUB surface, and specifically that a hub
// nobody configured behaves exactly as it did before this feature existed.
// The end-to-end proof (an impostor refused over a real socket) is p2p_authpsk.
// ---------------------------------------------------------------------------
static void Test_LoginAuth()
{
    TF_CASE("the login authenticator passes its own battery")
    {
        TF_CHECK(p2pauth::AuthSelfTest());
    }

    TF_CASE("an unconfigured hub REQUIRES auth, signs nothing, and will not arm")
    {
        // The posture, asserted rather than assumed - and it INVERTED on
        // 2026-08-18 (ProductionPlan.md Stage 3 step 8). This case used to
        // read "an unconfigured hub requires nothing", which was the opt-in
        // guarantee that kept every existing deployment behaving as it did.
        // That guarantee is what the step deliberately withdrew: off-by-saying-
        // nothing meant the deployments that most needed verification were the
        // ones that never asked for it.
        //
        // Requiring it and being unable to enforce it is not a protection, so
        // the third check is the one that matters: such a hub does not start.
        // Full coverage of all five arming outcomes is p2p_armgate.
        P2PeerHub oHub(L"AuthSuite.Bare");
        TF_CHECK(oHub.IsAuthRequired());
        TF_CHECK(!oHub.CanAuthSign());
        TF_CHECK_EQ(oHub.AuthArm(), p2pauth::ArmNoIdentity);
        TF_CHECK(!oHub.CreateHub(L"AuthSuite.Bare"));
    }

    TF_CASE("the flat C surface can provision a hub and read back why it will not arm")
    {
        // ProductionPlan.md Stage 3 step 8 added these entry points, and the
        // reason they had to be added is the point of the case: RequireAuth
        // defaults to ON, and Targetcore_c.h is the ONLY surface a
        // redistributed build offers. Without them the default flip would
        // have been a hard break with no migration reachable from C at all -
        // no way to provision, and no way to opt out.
        P2PeerHubHandle hHub = p2peerhub_create(L"AuthSuite.FlatC");
        TF_CHECK(hHub != nullptr);

        TF_CHECK_EQ(p2peerhub_is_auth_required(hHub), 1);
        TF_CHECK_EQ(p2peerhub_auth_arm(hHub), (int)p2pauth::ArmNoIdentity);
        TF_CHECK(p2peerhub_auth_arm_text(p2peerhub_auth_arm(hHub)) != nullptr);
        TF_CHECK(p2peerhub_auth_allow_list_path(hHub) == nullptr);

        const std::string sKey = IdTempPath("flatckey");
        DeleteFileA(sKey.c_str());
        DeleteFileA((sKey + ".pub").c_str());

        char szFp[p2pcng::kIdFingerprintLen] = { 0 };
        int  nCreated = 0;
        TF_CHECK_EQ(p2peerhub_provision_auth(hHub, sKey.c_str(), szFp,
                                             (unsigned long)sizeof(szFp), &nCreated),
                    (int)p2pcng::IdOk);
        TF_CHECK_EQ(nCreated, 1);
        TF_CHECK(szFp[0] != 0);

        // The identity is half of it. The allow-list is the operator's half,
        // and the arm result now says so rather than repeating itself.
        TF_CHECK_EQ(p2peerhub_auth_arm(hHub), (int)p2pauth::ArmNoAllowList);

        // The migration, over the same surface.
        p2peerhub_require_auth(hHub, 0);
        TF_CHECK_EQ(p2peerhub_is_auth_required(hHub), 0);
        TF_CHECK_EQ(p2peerhub_auth_arm(hHub), (int)p2pauth::ArmNotRequired);

        p2peerhub_destroy(hHub);
        DeleteFileA(sKey.c_str());
        DeleteFileA((sKey + ".pub").c_str());
    }

    TF_CASE("a missing identity file is a named startup failure, not a silent one")
    {
        P2PeerHub oHub(L"AuthSuite.Missing");
        const std::string sNone = IdTempPath("authnone");
        DeleteFileA(sNone.c_str());

        TF_CHECK_EQ(oHub.SetIdentity(sNone.c_str()), p2pcng::IdErrNotFound);
        // ...and the hub is left unable to sign rather than half-configured.
        TF_CHECK(!oHub.CanAuthSign());
    }

    TF_CASE("a configured hub can sign, and enforcement is a separate switch")
    {
        P2PeerHub oHub(L"AuthSuite.Keyed");
        const std::string sKey = IdTempPath("authkey");
        DeleteFileA(sKey.c_str());

        // bCreateIfAbsent: first run generates and protects the key.
        TF_CHECK_EQ(oHub.SetIdentity(sKey.c_str(), true), p2pcng::IdOk);
        TF_CHECK(oHub.CanAuthSign());

        // Holding a key is not the same as demanding one from the peer, and
        // the two are deliberately not coupled. What changed on 2026-08-18 is
        // only which way the switch starts: demanding is now the default, so
        // the round trip is asserted from ON rather than from OFF.
        TF_CHECK(oHub.IsAuthRequired());
        oHub.RequireAuth(false);
        TF_CHECK(!oHub.IsAuthRequired());
        oHub.RequireAuth(true);
        TF_CHECK(oHub.IsAuthRequired());

        // A key alone still does not arm the hub: the allow-list is the half
        // that says WHO, and no library can supply it.
        TF_CHECK_EQ(oHub.AuthArm(), p2pauth::ArmNoAllowList);

        DeleteFileA(sKey.c_str());
    }

    TF_CASE("a malformed allow-list is refused whole, not loaded in part")
    {
        P2PeerHub oHub(L"AuthSuite.Allow");
        const std::string sAllow = IdTempPath("authallow");
        DeleteFileA(sAllow.c_str());

        p2pcng::EcdsaP256 oPeer;
        unsigned char pub[p2pcng::kEcdsaPubLen] = { 0 };
        TF_CHECK(oPeer.Generate());
        TF_CHECK(oPeer.ExportPublic(pub));
        TF_CHECK_EQ(p2pcng::AppendAllowList(sAllow.c_str(), "AuthSuite.Peer", pub),
                    p2pcng::IdOk);
        TF_CHECK_EQ(oHub.SetAllowList(sAllow.c_str()), p2pcng::IdOk);

        // Append a line that is not an entry. A partially loaded allow-list is
        // the dangerous outcome - it silently drops peers - so the load fails
        // as a whole and the hub keeps the list it already validated.
        HANDLE h = CreateFileA(sAllow.c_str(), FILE_APPEND_DATA, 0, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        TF_CHECK(h != INVALID_HANDLE_VALUE);
        if (h != INVALID_HANDLE_VALUE)
        {
            const char szJunk[] = "AuthSuite.Broken notahexkey\r\n";
            DWORD cbWritten = 0;
            WriteFile(h, szJunk, (DWORD)(sizeof(szJunk) - 1), &cbWritten, nullptr);
            CloseHandle(h);
            TF_CHECK_EQ(oHub.ReloadAllowList(), p2pcng::IdErrFormat);
        }

        DeleteFileA(sAllow.c_str());
    }
}

// ---------------------------------------------------------------------------
// Payload cypher (P2PeerioGcm) and the frame seam it plugs into.
//
// GcmCryptoSelfTest() carries the cipher battery - round trip, nonce freshness,
// bit-flip detection in all three regions of the sealed frame, truncation, and
// the wrong key. What is added here is the part the self-test cannot reach: the
// P2Piomage geometry, i.e. that a frame which GREW by 28 bytes still describes
// itself correctly in a header that is not itself encrypted.
//
// The forgery path is deliberately not driven here. DecryptP2PiomageSwap()
// answers a tag failure by posting P2Pmsg_CypherEx, which dereferences m_pCon -
// null on a P2Peerio that was never registered against a connection. Detection
// itself is covered at the cipher level in GcmCryptoSelfTest; the end-to-end
// proof that a forged frame drops the connection belongs to p2p_authrelay.
// ---------------------------------------------------------------------------
static void Test_PayloadCypher()
{
    TF_CASE("the payload cypher passes its own battery")
    {
        TF_CHECK(GcmCryptoSelfTest());
    }

    TF_CASE("an unconfigured P2Peerio is still a plaintext passthrough")
    {
        // The opt-in guarantee at the crypto seam, matching the one asserted
        // for the hub above: no cypher posted means the frame is handed back
        // by identity, pointer and all.
        P2Peerio oIo;
        const char szBody[] = "unsealed";
        P2Piomage *pPlain = P2Piomage_Alloc(szBody, (UINT32)sizeof(szBody));

        TF_CHECK(oIo.EncryptP2PiomageSwap(pPlain) == pPlain);
        TF_CHECK(oIo.DecryptP2PiomageSwap(pPlain) == pPlain);

        P2Piomage_Release(pPlain);
    }

    TF_CASE("a sealed frame grows by nonce+tag and says so in its header")
    {
        unsigned char aKey[p2pcng::kAesKeyLen];
        for (size_t i = 0; i < sizeof(aKey); ++i)
            aKey[i] = (unsigned char)(i + 3);

        P2PeerioGcm *pGcm = new P2PeerioGcm();
        pGcm->SetKey((const char *)aKey, (int)sizeof(aKey), 0, 0);

        P2Peerio oIo;
        oIo.PostP2Pcrypto(pGcm);      // takes ownership

        const char szBody[] = "sealed payload, header in clear";
        P2Piomage *pPlain = P2Piomage_Alloc(szBody, (UINT32)sizeof(szBody));
        const UINT nPlainBody  = IOmage_Sizeof(pPlain);
        const UINT nPlainFrame = P2Piomage_Sizeof(pPlain);

        const P2Piomage *pSealed = oIo.EncryptP2PiomageSwap(pPlain);
        TF_CHECK(pSealed != pPlain);

        // 12-byte nonce + 16-byte tag, on the body and therefore on the frame.
        TF_CHECK(IOmage_Sizeof(pSealed)    == nPlainBody  + 28);
        TF_CHECK(P2Piomage_Sizeof(pSealed) == nPlainFrame + 28);

        // The header is readable without the key - that is what lets a
        // receiver size its buffer before it can authenticate anything.
        TF_CHECK(VBLock_SyncAddr(pSealed->oSync.uiSync1) ==
                 VBLock_SyncAddr(pPlain->oSync.uiSync1));
        TF_CHECK(pSealed->oSync.uiSync2 == ~pSealed->oSync.uiSync1);

        // ...and the body genuinely is not the plaintext.
        TF_CHECK(memcmp(&pSealed->cIOmage, &pPlain->cIOmage, nPlainBody) != 0);

        // Round trip restores the original frame exactly, header included.
        P2Piomage *pOpened = oIo.DecryptP2PiomageSwap(pSealed);
        TF_CHECK(pOpened != 0);
        if (pOpened)
        {
            TF_CHECK(IOmage_Sizeof(pOpened)    == nPlainBody);
            TF_CHECK(P2Piomage_Sizeof(pOpened) == nPlainFrame);
            TF_CHECK(memcmp(&pOpened->cIOmage, &pPlain->cIOmage, nPlainBody) == 0);
            P2Piomage_Release(pOpened);
        }

        P2Piomage_Release(pPlain);
    }
}

// ---------------------------------------------------------------------------
// End-to-end payload seal (p2pseal). Distinct from the connection cypher: that
// one protects a HOP, and an intermediate hub necessarily decrypts it because
// routing is decided on the destination address. This seals the BODY to the
// destination, so every hub on the path can route it and none can read it.
//
// SealSelfTest() carries the battery - round trip, wrong recipient, wrong
// sender, the body moved to another address pair, a bit flipped in each of the
// five regions, truncation, and a verify-only key refusing to sign. What is
// added here is the property an intermediate hub actually depends on, asserted
// against the raw bytes rather than inside the module that produced them.
// ---------------------------------------------------------------------------
static void Test_EndToEndSeal()
{
    TF_CASE("the end-to-end seal passes its own battery")
    {
        TF_CHECK(p2pseal::SealSelfTest());
    }

    TF_CASE("a sealed body carries no trace of the plaintext")
    {
        p2pcng::EcdsaP256 oSender;   // A's identity
        p2pcng::EcdhP256  oRecip;    // C's static agreement key
        TF_CHECK(oSender.Generate());
        TF_CHECK(oRecip.Generate());

        unsigned char aSenderPub[p2pcng::kEcdsaPubLen];
        unsigned char aRecipAgree[p2pcng::kEcdhPubLen];
        TF_CHECK(oSender.ExportPublic(aSenderPub));
        TF_CHECK(oRecip.ExportPublic(aRecipAgree));

        const char szSecret[] = "top-secret-payload";
        const size_t cbPlain  = sizeof(szSecret);
        const size_t cbSealed = p2pseal::SealedSize(cbPlain);

        std::vector<unsigned char> vSealed(cbSealed);
        size_t cbGot = 0;
        TF_CHECK(p2pseal::Seal(oSender, aRecipAgree,
                               L"VNet1:Root", L"VNet1:Root.B.C",
                               szSecret, cbPlain,
                               &vSealed[0], cbSealed, &cbGot) == p2pseal::SealOk);
        TF_CHECK(cbGot == cbSealed);
        // ver 1 + sealed_at 8 + eph 64 + count 1 + slot 68 + nonce 12
        //   + tag 16 + sig 64 = 234, for ONE reader.
        // Was 156 until the v1 format (Stage 3 step 10) put a version byte and
        // a signed timestamp in front, and 165 until v2 (Stage 3 step 20) made
        // the body a multi-recipient envelope: the content key is now random
        // and wrapped once per reader, which is what lets a sender name an
        // intermediate hub that may read. One reader costs one 68-byte slot.
        // The literal is spelled out rather than written as kSealOverhead on
        // purpose: this case exists to NOTICE a size change, and one that
        // tracked the constant would agree with any change automatically -
        // which is exactly what it did not do here, and why this line had to
        // be edited by hand twice now.
        TF_CHECK(cbSealed == cbPlain + 234);

        // This is the assertion the intermediate hub rests on, and the same one
        // the Java EndToEndDirectTest makes about what B observes.
        bool bLeaked = false;
        for (size_t i = 0; i + cbPlain <= cbSealed; ++i)
            if (memcmp(&vSealed[i], szSecret, cbPlain) == 0) { bLeaked = true; break; }
        TF_CHECK(!bLeaked);

        // ...and the destination still recovers it exactly.
        std::vector<unsigned char> vOpened(cbPlain);
        TF_CHECK(p2pseal::Open(oRecip, aSenderPub,
                               L"VNet1:Root", L"VNet1:Root.B.C",
                               &vSealed[0], cbSealed,
                               &vOpened[0], cbPlain, &cbGot) == p2pseal::SealOk);
        TF_CHECK(cbGot == cbPlain);
        TF_CHECK(memcmp(&vOpened[0], szSecret, cbPlain) == 0);
    }

    TF_CASE("an intermediate holding no keys cannot open what it forwards")
    {
        // B is a hub with no end-to-end keys at all - the case the Java test
        // builds explicitly ("intermediate: no keys"). It can route the message
        // because src and dst are in clear, and that is the whole of what it can do.
        p2pcng::EcdsaP256 oSender;
        p2pcng::EcdhP256  oRecip, oIntermediate;
        TF_CHECK(oSender.Generate());
        TF_CHECK(oRecip.Generate());
        TF_CHECK(oIntermediate.Generate());   // B's own key, unrelated to the pair

        unsigned char aSenderPub[p2pcng::kEcdsaPubLen];
        unsigned char aRecipAgree[p2pcng::kEcdhPubLen];
        TF_CHECK(oSender.ExportPublic(aSenderPub));
        TF_CHECK(oRecip.ExportPublic(aRecipAgree));

        const char szSecret[] = "not for the middle";
        const size_t cbPlain  = sizeof(szSecret);
        const size_t cbSealed = p2pseal::SealedSize(cbPlain);

        std::vector<unsigned char> vSealed(cbSealed);
        std::vector<unsigned char> vOpened(cbPlain);
        TF_CHECK(p2pseal::Seal(oSender, aRecipAgree,
                               L"VNet1:Root", L"VNet1:Root.B.C",
                               szSecret, cbPlain,
                               &vSealed[0], cbSealed, 0) == p2pseal::SealOk);

        // B has a perfectly good agreement key. It is simply not the one the
        // body was sealed to, and holding a key is not the same as being the
        // recipient.
        //
        // SealErrNotAReader since v2 (Stage 3 step 20), where this said
        // SealErrTag. Not a weakening - a sharpening. Under v1 the wrong key
        // derived the wrong secret and the GCM tag failed, which is the right
        // outcome reached by the only route available. v2 looks for this
        // reader's slot tag first, finds none, and can therefore say WHICH of
        // the two things went wrong. That distinction is what a relay needs:
        // "this body is not addressed to me" means forward it, "this body is
        // damaged" means drop it, and SealErrTag alone could not tell a hub
        // which one it was holding.
        TF_CHECK(p2pseal::Open(oIntermediate, aSenderPub,
                               L"VNet1:Root", L"VNet1:Root.B.C",
                               &vSealed[0], cbSealed,
                               &vOpened[0], cbPlain, 0) == p2pseal::SealErrNotAReader);
    }
}

// ---------------------------------------------------------------------------
// A BIG undeliverable message must still be reported.
//
// The report embeds the message it reports on, so it is always LARGER than the
// thing that failed - and it is built in a 16-bit addressed message heap, which
// stops at 65535 bytes. Nothing bounded either side of that, and the message was
// embedded TWICE: once as the wrap, and once again inside the diagnostic event
// AFPmsg() deep-copied it into, which ExceptionFactory then attaches.
//
// Measured on Windows, Debug, before the fix (report = IOMAGE, i.e. what a send
// would put on the wire). Off Windows this path failed earlier and differently -
// see the ring-pointer note in WrappedResponseFactory - so these sizes were
// never reachable there:
//
//     payload   message   report        outcome
//       8000      8991     22574        fine
//      29000     29991     64574        fine, and 961 bytes from the ceiling
//      30000     30991        --        THREW "Internal VBHeapRoot.uVBLockAddr=1
//                                       corruption" from VBHeapRoot_SetFree
//                                       (aFree=65561), on the ROUTING HUB'S
//                                       PUMP THREAD, and no report was sent
//
// A stock peer may send 32768 bytes (P2Peerio::m_dwMaxRecvSize), so that band is
// reachable by any logged-in peer and by any application posting a large message
// to an address that has just gone away. The pump caught the throw and the hub
// survived - measured, and it is why this is a lost-report defect rather than a
// denial of service - but the sender was never told, and the P2Pevent built for
// the report leaked on the way out.
//
// The fix is in two places because the two copies are bounded by different
// things: RouteP2PeerMsg no longer copies the message into the event, and
// WrappedResponseFactory elides the embedded body past MAX_P2PmsgWrapEmbed.
//
// WHAT THESE CASES DO NOT COVER, stated so a green run is not over-read. They
// guard the HEAP limit. They do not guard the second one - a report that is
// built but still too big for the receiver to accept (32768) - because they
// build the diagnostic event themselves and so cannot see RouteP2PeerMsg's.
// Measured: with the body elided but AFPmsg() restored, every case here passes
// and p2p_bigreport is the sole red, failing at 38424 bytes with the connection
// dropped. That test is the guard on that half.
static void Test_UndeliverableReportBounded()
{
    // The size that threw. Chosen from the measurement above rather than from
    // the top of the range, so this case sits exactly where the defect started.
    static const int kBigPayload = 30000;

    TF_CASE("a big undeliverable message is still reported")
    {
        static const P2PaddrSTR kHub = L"BigReport.Hub";

        CascadeHub oHub(kHub);
        oHub.RequireAuth ( false );
        HANDLE     hThread = oHub.SpawnHub();
        TF_CHECK(hThread != NULL);

        if (hThread)
        {
            std::vector<char> vPayload((size_t)kBigPayload, 'A');
            PostP2Pmsg(new P2PeerMsg32(L"BigReport.Src", L"BigReport.Dst",
                                       P2Pmsg_BCast, &vPayload[0],
                                       (P2Psize_t)kBigPayload),
                       oHub.GetHubID());
            Sleep(1500);

            // Two laps: the seed, and the report about it. Without the fix the
            // report throws while being built, so the count stops at 1 - the
            // message is never answered at all. (The report is itself
            // undeliverable here, which is what session 31's cap drops; it is
            // counted first, in PeekP2PeerMsg, before that decision.)
            TF_CHECK_EQ(oHub.m_nRouted.load(), 2);
        }

        oHub.CloseHub();
        if (hThread) { WaitForSingleObject(hThread, 3000); CloseHandle(hThread); }
    }

    TF_CASE("the report fits down the wire, and stays a wrapped message")
    {
        std::vector<char> vPayload((size_t)kBigPayload, 'A');
        P2PeerMsg32 oMsg(L"BigReport.Src", L"BigReport.Dst", P2Pmsg_BCast,
                         &vPayload[0], (P2Psize_t)kBigPayload);

        // The event RouteP2PeerMsg builds - deliberately WITHOUT AFPmsg(), so
        // this measures what the live path now produces.
        P2Pevent* pEVT = EVERR->MODULE
                              ->Message_T("Message not deliverable")
                              ->Advice_T("Connection lost")
                              ->HResult(P2Pevent_UNDELIVERABLE)
                              ->Group("P2P");
        P2PeerMsg* pReport = oMsg.ExceptionFactory(pEVT);
        pEVT->Cancel();
        TF_CHECK(pReport != nullptr);

        if (pReport)
        {
            // It must fit inside what a peer will accept, or the frame is
            // refused on arrival and the connection dropped - a second way for
            // the sender not to be told. Measured at 8280 bytes with the body
            // elided; the bound is the transport's own maximum.
            pReport->PrepareP2Piomage(~(DWORD)0);
            const UINT nImage = pReport->P2PiomageSize();
            pReport->ReleaseP2Piomage();
            TF_CHECK(nImage <= (UINT)MAX_P2Psize);

            // Eliding the BODY must not stop it being a wrapped message: the
            // stock On_MsgCatch reaches (*pMsg)[1], and an application may
            // unwrap. Name and addresses survive; the payload does not.
            TF_CHECK(pReport->IsWrapped());
            P2PeerMsg* pBack = pReport->UnwrapFactory();
            TF_CHECK(pBack != nullptr);
            if (pBack)
            {
                TF_CHECK(wcscmp(pBack->GetSource(), L"BigReport.Src") == 0);
                TF_CHECK(wcscmp(pBack->GetDestin(), L"BigReport.Dst") == 0);
                TF_CHECK_EQ((int)pBack->DataSize(), 0);
                delete pBack;
            }
            delete pReport;
        }
    }

    TF_CASE("a small undeliverable message still carries its body back")
    {
        // The elision is a bound, not a policy change: under it, nothing about
        // the report changes. This is the half that would silently disappear if
        // the bound were ever set too low.
        static const int kSmallPayload = 256;
        std::vector<char> vPayload((size_t)kSmallPayload, 'B');
        P2PeerMsg32 oMsg(L"BigReport.Src", L"BigReport.Dst", P2Pmsg_BCast,
                         &vPayload[0], (P2Psize_t)kSmallPayload);

        P2Pevent* pEVT = EVERR->MODULE
                              ->Message_T("Message not deliverable")
                              ->HResult(P2Pevent_UNDELIVERABLE)
                              ->Group("P2P");
        P2PeerMsg* pReport = oMsg.ExceptionFactory(pEVT);
        pEVT->Cancel();

        if (pReport)
        {
            P2PeerMsg* pBack = pReport->UnwrapFactory();
            TF_CHECK(pBack != nullptr);
            if (pBack)
            {
                TF_CHECK_EQ((int)pBack->DataSize(), kSmallPayload);
                const char* pData = pBack->Data();
                TF_CHECK(pData != nullptr);
                if (pData)
                    TF_CHECK(memcmp(pData, &vPayload[0], kSmallPayload) == 0);
                delete pBack;
            }
            delete pReport;
        }
    }
}

// ---------------------------------------------------------------------------
void RunTargetcoreSuite()
{
    Test_MessageValuePlumbing();
    Test_AddrNameAccessors();
    Test_InMemoryTwoHubDelivery();
    Test_UndeliverableCascade();
    Test_UndeliverableReportBounded();
    // Restored 2026-08-14 with the ABI they cover. The note that stood here
    // said these were "preserved in MSCS_JavaBindings\Targetcore\" -- only the
    // wrapper SOURCES were ever copied there, never these cases, and that copy
    // has since been deleted too (it had fallen several fixes behind). They are
    // still the only cases in the tree that drive the flat C surface.
    Test_CApiHubSink();
    Test_CApiHandleGuards();
    Test_CryptoSelfTest();
    Test_IdentityStore();
    Test_LoginAuth();
    Test_PayloadCypher();
    Test_EndToEndSeal();
}
