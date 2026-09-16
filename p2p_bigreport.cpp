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
// p2p_bigreport.cpp — an undeliverable message is answered with a report that
// EMBEDS it, and nothing checks that the report still fits down the wire.
//
// ---------------------------------------------------------------------------
// THE MECHANISM
//
//   P2PeerTarget::RouteP2PeerMsg answers an undeliverable message with a
//   P2Pmsg_Exception built by P2PeerMsg::WrappedResponseFactory, and that
//   factory embeds the WHOLE undeliverable message as a BLOB16 item inside the
//   new one. The response was therefore always LARGER than the thing it
//   reported on, and TWO different limits sat above it, each unchecked:
//
//     1. The response is built in a 16-bit addressed message heap - 65535
//        bytes. And the message went in TWICE: once as the wrap, and once more
//        inside the diagnostic event, because AFPmsg() deep-copies it. So the
//        response ran to a little over double the message. Measured, Debug:
//
//            payload   message   response(IOMAGE)   outcome
//              8000      8991      22574            fine
//             29000     29991      64574            fine, 961 from the ceiling
//             30000     30991         --            THREW, no report sent
//
//        The throw is "Internal VBHeapRoot.uVBLockAddr=1 corruption" out of
//        VBHeapRoot_SetFree(aFree=65561), on the ROUTING HUB'S PUMP THREAD.
//        The pump catches it and the hub survives - measured here in stage 3 -
//        so this is a lost report, not a downed hub.
//
//     2. Even when it is built, the response has to be RECEIVABLE. The default
//        limit is 32768 (P2Peerio::m_dwMaxRecvSize) and an over-size frame is
//        refused with "Attempt to exceed maximum (32768) buffer size (38424)"
//        -> Throw() -> the connection is DROPPED.
//
//   Either way the sender is not told its message was undeliverable. In case 1
//   nothing comes back at all; in case 2 the link goes down instead.
//
//   Note which way round this is. The oversize frame is not something an
//   attacker sends. It is something the LIBRARY manufactures, on its own pump
//   thread, in response to an ordinary message, and then transmits.
//
// WHY THE PREVIOUS ROUND OF THIS DID NOT CATCH IT
//
//   Session 31 capped the undeliverable-report CASCADE: an undeliverable
//   exception is now dropped instead of being answered with another exception
//   wrapping it. That fixed the runaway. It says nothing about a single report
//   that is simply too big, which needs no cascade at all — one lap, one
//   message, one report that cannot be built or cannot be received. Its own
//   note recorded exactly this as open: "a single WrappedResponseFactory still
//   embeds an entire message".
//
// WHAT THIS TEST GUARDS THAT THE UNIT SUITE DOES NOT
//
//   The fix has two halves and they fail differently. TargetcoreSuite's cases
//   cover the heap half (limit 1). They do NOT cover limit 2: with the body
//   elided but AFPmsg() restored, the whole unit suite is GREEN and this test
//   fails at 38424 bytes with the connection dropped. Measured, both ways.
//
// ---------------------------------------------------------------------------
// WHAT IT DOES — two real hubs, one real socket, stock configuration.
//
//       Report.Root            (service, the PARENT)
//          |
//       Report.Root.Leaf       (client,  the CHILD — the one that gets hurt)
//
//   The Leaf posts a BCast addressed to "Ghost.Nowhere", which exists nowhere
//   in the tree. Routing at the Leaf sends anything not below itself UP to its
//   parent; the Root has no connection that can reach it either, so the Root
//   raises the undeliverable report and posts it back to the Leaf.
//
//   1. CONTROL — a 64-byte payload. The report is ~4 KB, fits, and arrives at
//      the Leaf's P2Pmsg_Exception handler. This proves the whole path works:
//      the address really is unroutable, the report really is raised, and it
//      really does come back. Without it a silence in stage 2 would be
//      indistinguishable from a broken transport.
//
//   2. THE DEFECT — a 30000-byte payload. Same route, same everything. The
//      report is ~36 KB and the Leaf cannot receive it.
//
// VERDICT = process EXIT CODE:
//   0  PASS   the second report arrived too — the report is bounded to
//             something the peer can receive
//   1  FAIL   the second report never arrived. Either the connection was
//             dropped on the oversize frame or the frame was refused silently.
//             The sender was not told, and this is the defect
//   2  SETUP  startup / factory failure (test inconclusive)
//   3  INCONCLUSIVE the control report never arrived, so stage 2 proves
//             nothing. NOT a pass
//
// A NOTE ON WHAT IS BEING ASSERTED. This test does not care HOW the report is
// bounded — truncating the embedded copy, omitting it, or fragmenting are all
// fixes it would accept. It asserts only that a peer which sends an ordinary
// message to a bad address is TOLD SO, and keeps its connection.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <exception>
#ifdef _WIN32
#  include <crtdbg.h>          // headless assert trap - a dialog would hang ctest
#endif

// ---------------------------------------------------------------------------
static const P2PaddrSTR kRootAddr  = L"Report.Root";        // the PARENT hub
static const P2PaddrSTR kLeafAddr  = L"Report.Root.Leaf";   // the CHILD hub
static const P2PaddrSTR kGhostAddr = L"Ghost.Nowhere";      // routable nowhere

// The control payload is small enough that the report certainly fits; the big
// one is chosen so the report (payload + ~5.4 KB) clears the 32768-byte
// receive limit without being anywhere near a message-size limit itself.
static const int kSmallPayload =    64;
static const int kBigPayload   = 30000;

static HANDLE      g_hLoggedIn  = NULL;   // the Root has a logged-in child
static HANDLE      g_hReport    = NULL;   // an exception report reached the Leaf
static HANDLE      g_hConClose  = NULL;   // the Leaf's connection went down
static int         g_nReports   = 0;      // how many reports the Leaf has seen

static void Log(const char* msg)
{
    std::printf("[bigreport] %s\n", msg);
    std::fflush(stdout);
}

// A debug ASSERT on a pump thread pops a modal dialog under ctest (session 22)
// and an unhandled throw takes the process out with no explanation at all -
// which is exactly what this test hit first: exit 3, no output. Both are folded
// into a printed line here so a failure names itself.
#ifdef _WIN32
static int __cdecl AssertReportHook(int nReportType, char* szMsg, int* pnRet)
{
    if (nReportType == _CRT_ASSERT)
    {
        std::fflush(stdout);
        std::fprintf(stderr, "[bigreport] ASSERT: %s", szMsg ? szMsg : "(none)");
        std::fflush(stderr);
        if (pnRet) *pnRet = 0;      // do not launch the debugger
        return TRUE;                // handled -> continue, as Release would
    }
    return FALSE;
}
#endif

static void OnTerminate()
{
    std::fflush(stdout);
    std::fprintf(stderr, "[bigreport] TERMINATE - an exception escaped a thread\n");
    std::fflush(stderr);
    std::abort();
}

static std::string N(const wchar_t* w)
{
    std::string s;
    if (w) for (; *w; ++w) {
        unsigned long c = (unsigned long)*w;
        s.push_back(c < 0x80 ? (char)c : '?');
    }
    return s;
}

// =========================================================================
class ReportHub : public P2PeerHub
{
public:
    ReportHub(P2PaddrSTR strAddr, bool bRoot)
        : P2PeerHub(strAddr), m_bRoot(bRoot) {}
    virtual ~ReportHub() {}

    // Posted from main() so the two stages are strictly ordered.
    void PostToNowhere(int nBytes)
    {
        std::vector<char> vPayload((size_t)nBytes, 'A');
        PostP2PeerMsg(new P2PeerMsg32(kLeafAddr, kGhostAddr, P2Pmsg_BCast,
                                      &vPayload[0], (P2Psize_t)nBytes));
        std::printf("[bigreport] LEAF posted a %d-byte BCast to '%s'\n",
                    nBytes, N(kGhostAddr).c_str());
        std::fflush(stdout);
    }

protected:
    // Every message this hub routes, named. Kept rather than removed: the
    // failure this test was written for produces SILENCE at the routing hub,
    // and a trace showing the message arriving and nothing coming back is what
    // distinguishes that from a message that never left.
    virtual msgRESULT PeekP2PeerMsg(P2PeerMsg* pMsg) override
    {
        std::printf("[bigreport] %s routing '%s' %s -> %s\n",
                    m_bRoot ? "ROOT" : "LEAF",
                    pMsg ? N(pMsg->c_name()).c_str()    : "<null>",
                    pMsg ? N(pMsg->GetSource()).c_str() : "<null>",
                    pMsg ? N(pMsg->GetDestin()).c_str() : "<null>");
        std::fflush(stdout);
        return P2PeerHub::PeekP2PeerMsg(pMsg);
    }

    // THE ARRIVAL THIS TEST WAITS ON, and it is not the obvious one. The report
    // is a P2Pmsg_Exception WRAPPING the undeliverable message, and dispatch
    // matches on the name of the message it wraps - so a report about a BCast
    // lands in P2PeerHub's ON_P2PeerMsg_CATCH(P2Pmsg_BCast, On_MsgCatch) entry,
    // not in the ON_P2PeerMsg_CATCH(P2Pmsg_Exception, ...) one. Both are
    // counted below so the test cannot be fooled by that routing detail.
    virtual msgRESULT On_MsgCatch(P2PeerMsg* pMsg) override
    {
        if (!m_bRoot)
            NoteReport(pMsg, "On_MsgCatch");
        return P2PeerHub::On_MsgCatch(pMsg);
    }

    virtual msgRESULT On_MsgCatchCatch(P2PeerMsg* pMsg) override
    {
        if (!m_bRoot)
            NoteReport(pMsg, "On_MsgCatchCatch");
        return P2PeerHub::On_MsgCatchCatch(pMsg);
    }

    void NoteReport(P2PeerMsg* pMsg, const char* pszWhere)
    {
        ++g_nReports;
        std::printf("[bigreport] LEAF received report #%d via %s: '%s' from '%s'\n",
                    g_nReports, pszWhere,
                    pMsg ? N(pMsg->c_name()).c_str()   : "<null>",
                    pMsg ? N(pMsg->GetSource()).c_str(): "<null>");
        std::fflush(stdout);
        if (g_hReport) SetEvent(g_hReport);
    }

    // The failure signature: instead of a report, the link goes down.
    virtual conRESULT On_ConClose(P2PeerCon* pCon) override
    {
        if (!m_bRoot)
        {
            Log("LEAF connection CLOSED");
            if (g_hConClose) SetEvent(g_hConClose);
        }
        return P2PeerHub::On_ConClose(pCon);
    }

    virtual conRESULT On_ConLogin(P2PeerCon*  pCon,
                                  P2PaddrSTR  strThatP2Paddr,
                                  const void* pvLoginMsg,
                                  P2Psize_t   iSize) override
    {
        conRESULT result = P2PeerHub::On_ConLogin(pCon, strThatP2Paddr,
                                                  pvLoginMsg, iSize);
        if (m_bRoot)
        {
            std::printf("[bigreport] ROOT: login FROM '%s'\n",
                        N(strThatP2Paddr).c_str());
            std::fflush(stdout);
            if (g_hLoggedIn) SetEvent(g_hLoggedIn);
        }
        return result;
    }

private:
    bool m_bRoot;
};

// =========================================================================
int main(int argc, char* argv[])
{
    short nPort = (argc >= 2) ? (short)atoi(argv[1]) : 7823;

    std::printf("=== p2p_bigreport - the undeliverable report that cannot be "
                "delivered either ===\n");
    std::printf("Port : %d\n", (int)nPort);
    std::fflush(stdout);

#ifdef _WIN32
    _CrtSetReportHook(AssertReportHook);
#endif
    std::set_terminate(OnTerminate);

    g_hLoggedIn = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hReport   = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hConClose = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16)) { Log("SETUP: StartupP2Pmsg() failed"); return 2; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);

    int nExit = 2;
    {
        ReportHub oRoot(kRootAddr, true);
        ReportHub oLeaf(kLeafAddr, false);

        //  RequireAuth(false): this is a FRAMING test - a report larger than one
        //  frame, reassembled across reads - and nothing in it depends on who the
        //  peer is. Auth is required by default since Stage 3 step 8, so an
        //  unprovisioned hub would refuse to arm and the framing would go
        //  unmeasured.
        oRoot.RequireAuth ( false );
        //  RequireSeal(false) since 2026-08-21 (Stage 3 step 20), and it is the
        //  same argument as the RequireAuth(false) beside it: this is a RELAY
        //  test, not a confidentiality one. With the automatic seal on, a
        //  cross-branch message is sealed to its destination before it goes -
        //  and a hub with no agreement key for that destination DROPS it, so
        //  the topology under test never carries anything and the gate would
        //  measure the seal instead of the thing it is named after.
        //
        //  IT ALSO MEETS A REAL LIMIT, recorded here because this is where it
        //  shows: a BROADCAST has no single destination to seal to. The
        //  address lookup is exact, so P2PmsgBCast to a subtree finds no
        //  agreement key and is refused. Sealing and broadcast do not compose
        //  today - ProductionPlan.md Stage 3 step 20 carries it.
        oRoot.RequireSeal ( false );
        oLeaf.RequireAuth ( false );
        oLeaf.RequireSeal ( false );
        HANDLE hRootThread = oRoot.SpawnHub();
        HANDLE hLeafThread = oLeaf.SpawnHub();
        if (!hRootThread || !hLeafThread) { Log("SETUP: SpawnHub() failed"); return 2; }

        P2PeerConWsa* pSvc = P2PeerConWsa::ServiceFactory(kLeafAddr, nPort);
        if (!pSvc) { Log("SETUP: ServiceFactory failed"); return 2; }
        oRoot.PostP2PeerCon(pSvc);
        Log("root listening");

        Sleep(500);   // let the listener bind before dialling

        P2PeerConWsa* pCli = P2PeerConWsa::ClientFactory(kRootAddr, L"127.0.0.1", nPort);
        if (!pCli) { Log("SETUP: ClientFactory failed"); return 2; }
        oLeaf.PostP2PeerCon(pCli);
        Log("leaf dialling its parent");

        if (WaitForSingleObject(g_hLoggedIn, 15000) != WAIT_OBJECT_0)
        {
            std::printf("\nRESULT: SETUP - the leaf never completed a login.\n");
            nExit = 2;
        }
        else
        {
            Sleep(300);   // let the LoginAck land

            // ---- Stage 1: CONTROL -----------------------------------------
            oLeaf.PostToNowhere(kSmallPayload);

            if (WaitForSingleObject(g_hReport, 15000) != WAIT_OBJECT_0)
            {
                std::printf(
                  "\nRESULT: INCONCLUSIVE - the CONTROL report never came back,\n"
                  "  so the undeliverable path itself is not working here and\n"
                  "  stage 2 would prove nothing. This is NOT a pass. Check\n"
                  "  wsa_mesh and p2p_authancestor first (the report's source is\n"
                  "  the ghost address, so it reaches the leaf only through the\n"
                  "  ancestor exemption in the source-binding gate).\n");
                nExit = 3;
            }
            else
            {
                Log("control OK - a small undeliverable message IS reported back");

                // ---- Stage 2: the same thing, bigger ----------------------
                oLeaf.PostToNowhere(kBigPayload);
                Log("waiting 10s for the report on the big one...");

                HANDLE aWait[2] = { g_hReport, g_hConClose };
                DWORD  dwWait   = WaitForMultipleObjects(2, aWait, FALSE, 10000);

                if (dwWait == WAIT_OBJECT_0)
                {
                    std::printf(
                      "\nRESULT: PASS - the report on the %d-byte message came\n"
                      "  back too, so the undeliverable report is bounded to\n"
                      "  something the peer it is addressed to can receive.\n",
                      kBigPayload);
                    nExit = 0;
                }
                else if (dwWait == WAIT_OBJECT_0 + 1)
                {
                    std::printf(
                      "\nRESULT: FAIL - the connection was DROPPED instead of\n"
                      "  reporting. The report embedding the %d-byte message is\n"
                      "  larger than the 32768-byte receive limit, so the peer it\n"
                      "  was addressed to refused the frame and tore the link\n"
                      "  down. The sender is never told its message was\n"
                      "  undeliverable - it just loses the connection.\n",
                      kBigPayload);
                    nExit = 1;
                }
                else
                {
                    std::printf(
                      "\nRESULT: FAIL - no report and no close within 10s. The\n"
                      "  report on the %d-byte message went nowhere. Whatever\n"
                      "  swallowed it, the sender was not told.\n", kBigPayload);
                    nExit = 1;
                }

                // ---- Stage 3: is the ROUTING HUB still alive? -------------
                // The severity of stage 2 turns on this. One lost report is a
                // bad error path. A hub that stops routing for EVERY peer
                // because one message was too big is a denial of service that
                // any peer can trigger with one well-formed message.
                Log("liveness probe: repeating the CONTROL message");
                ResetEvent(g_hReport);
                oLeaf.PostToNowhere(kSmallPayload);
                if (WaitForSingleObject(g_hReport, 10000) == WAIT_OBJECT_0)
                    Log("LIVENESS: the routing hub still reports - it survived");
                else
                {
                    std::printf(
                      "\nLIVENESS: the routing hub NO LONGER REPORTS. The same\n"
                      "  control message that worked in stage 1 now goes\n"
                      "  unanswered, so the throw took the hub's pump with it and\n"
                      "  one oversize report has stopped routing for every peer.\n");
                    nExit = 1;
                }
            }
        }

        Log("shutdown begin");
        oLeaf.CloseHub();
        oRoot.CloseHub();
        WaitForSingleObject(hLeafThread, 3000);
        WaitForSingleObject(hRootThread, 3000);
        CloseHandle(hLeafThread);
        CloseHandle(hRootThread);
    }

    CleanupP2Pmsg();
    if (g_hLoggedIn) { CloseHandle(g_hLoggedIn); g_hLoggedIn = NULL; }
    if (g_hReport)   { CloseHandle(g_hReport);   g_hReport   = NULL; }
    if (g_hConClose) { CloseHandle(g_hConClose); g_hConClose = NULL; }
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
