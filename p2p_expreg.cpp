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
// p2p_expreg.cpp — SECURITY GATE TEST: can a peer register identities it does
// not hold into the Explorer registry, are those registrations ever reaped, and
// does the Explorer's one product ever reach the client that asked for it?
//
// BACKGROUND — the two residuals left by the M2 "Explorer" finding.
//
//   SECURITY_REVIEW M2's Explorer half was DOWNGRADED in session 23, and the
//   downgrade is correct as far as it goes:
//
//     * the registration path is DOWNSTREAM of the source-binding gate
//       (P2PeerCon::GateAppMsgInbound, P2PeerCon.cpp:2056-2068), and that gate
//       is NOT conditioned on RequireAuth — it keys only on ConState_Login and
//       a non-null m_oThatP2Paddr, so it is live at the stock posture;
//     * P2PeerExplorer::On_XCidConLogin (P2PeerExplorer.cpp:1279-1285) REFUSES
//       any client-declared address outright and server-assigns "<hub>.XC%i"
//       from a free slot, so an Explorer peer cannot choose its own identity
//       even with authentication off.
//
//   Two residuals survive that, and this test is the one that settles them.
//
//   (a) DESCENDANT FORGERY. The gate accepts the logged-in identity "or an
//       IsRable descendant of it":
//
//           !m_oThatP2Paddr.IsRable(pMsg->GetSource())     // P2PeerCon.cpp:2058
//
//       and IsRable (P2Peer.cpp:365-377) returns true for an exact match OR
//       any prefix ending on a hop boundary. So a peer holding CEX.XC0 may put
//       CEX.XC0.Ghost on a message, and On_P2PexpCtrl registers whatever
//       GetSource() says. Nothing anywhere asks whether that sub-identity
//       exists. Fixed by P2PexpReg_BindSource (P2PeerExplorer.cpp:202-217),
//       which folds any claimed source back onto the address the Explorer
//       ASSIGNED to the connection it arrived on.
//
//   (b) STALE REAPING. On_XCidConClose used to reap by the EXACT slot address,
//       not by prefix: the peer's own CEX.XC0 entry went, every CEX.XC0.*
//       entry it fabricated stayed, forever, on a registry that has no other
//       eviction path. Fixed by CListReg*_RemoveRable (:226-261), called from
//       On_XCidConClose (:1382-1384).
//
// ---------------------------------------------------------------------------
// This test encodes the REQUIREMENT ("only the identity the Explorer itself
// assigned may be registered, everything under it is released when it drops,
// and hub status reaches the client that registered for it"), not whatever the
// tree happens to do. Do not "fix" it by relaxing an assertion, and do not add
// WILL_FAIL — see MscsUnitTests/CMakeLists.txt for why.
// ---------------------------------------------------------------------------
//
// WHAT IT DOES — one Explorer-bearing hub, one anonymous client, over loopback
// TCP. The arrangement is forced by the protocol, not chosen for convenience:
//
//   server  "CEX"        P2PeerHub + P2PeerExplorer (expump), the Explorer
//                        service listening on CEX.XC*
//   client  ""           an ANONYMOUS hub. On_XCidConLogin throws unless the
//                        login carries a NULL source, so an Explorer client
//                        may not have an address of its own; it is given one —
//                        CEX.XC0 — in the LoginAck.
//
//   Phase 0 (THE LIBRARY ACTIVATION PATH): the Explorer is stood up by
//     P2PeerExpump_ACTIVATE (P2PeerExplorer.cpp:1767-1832) — the documented
//     helper, not a hand-rolled copy of it. The test then asserts the hub can
//     actually SEE it (GetP2PeerExpump()), and that a second activation is
//     refused rather than replacing the incumbent. Until session 24 ACTIVATE
//     spawned an expump and never registered it, so the hub saw nothing, no
//     message ever routed to the Explorer, and the caller held the only
//     pointer to an orphan.
//
//   Phase 1 (POSITIVE CONTROL A): the client completes the Explorer login and
//     is assigned CEX.XC0. Without this the run proves nothing — reported as
//     INCONCLUSIVE, not as a pass.
//
//   Phase 2 (POSITIVE CONTROL B): it registers HONESTLY — one P2PexpumpCtrl
//     carrying RHub, sourced CEX.XC0, the identity it actually holds. This
//     MUST appear in m_oCListRegHubs. A refusal and a dead transport are both
//     just silence otherwise, which is the trap p2p_authspoof and p2p_authpsk
//     both guard against with an inline control.
//
//   Phase 2b (DELIVERY): registering is only half a directory service. The
//     Explorer answers RHub with a P2PexpumpHub addressed to the registrant
//     (QueryP2PmsgExp_Hub, P2PeerExplorer.cpp:1443), and broadcasts an
//     UNADDRESSED P2PexpumpHub to every registered sink by redirecting it
//     (On_P2PmsgExp_Hub, :1630-1640). BOTH must land on the client. The
//     addressed answer is emitted first, by the base RHub handler; the
//     ProbeExplorer then asks for the broadcast, so a second arrival before
//     any further registration can only be the redirected one.
//
//   Phase 3 (ARM (a) — THE FORGERY): the same connection registers again,
//     sourced CEX.XC0.Ghost — a sub-identity the Explorer never assigned and
//     nothing holds. This MUST NOT appear in the registry.
//
//   Phase 4 (ARM (b) — THE REAPING): the client disconnects. On_XCidConClose
//     runs. CEX.XC0 MUST be gone (that is control B's other half — it proves
//     the reaper ran at all) and CEX.XC0.Ghost MUST be gone with it.
//
//   The registry is read from INSIDE the expump thread — the only thread that
//   mutates it — by overriding On_P2PexpCtrl and On_XCidConClose and sampling
//   after delegating to the base. Nothing is polled across threads.
//
// VERDICT = process EXIT CODE:
//   0  PASS   the honest registration landed, was answered AND broadcast to,
//             and was reaped; the forged descendant was refused
//   1  FAIL   a fabricated descendant was registered, and/or it survived the
//             disconnect => residual (a) and/or (b) confirmed
//   2  SETUP  startup / factory / expump failure (test inconclusive)
//   3  INCONCLUSIVE the Explorer never assigned an XCid, the HONEST
//             registration never landed, or its hub status never reached the
//             client — the path is dead, so the forgery result would prove
//             nothing. NOT a pass.
//
// Build (Linux): as p2p_authgate.cpp.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2Pmsg.h"
#include "P2PeerHub.h"
#include "P2PeerExplorer.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kHubAddr   = L"CEX";        // the Explorer-bearing hub
static const P2PaddrSTR kExpDomain = L"CEX.XC*";    // slots it hands out
static const P2PaddrSTR kAnonAddr  = L"";           // the client holds no address
static const wchar_t    kGhostLeaf[] = L".Ghost";   // the sub-identity nobody holds

static const UINT      kMaxECid    = 8;             // exploration slots to offer

static HANDLE g_hXCid     = NULL;   // the Explorer assigned us a slot
static HANDLE g_hRegLegit = NULL;   // the honest registration was processed
static HANDLE g_hRegGhost = NULL;   // the forged registration was processed
static HANDLE g_hClosed   = NULL;   // On_XCidConClose ran for our slot
static HANDLE g_hHubStat  = NULL;   // a P2PexpumpHub reached the client

// Sampled inside the expump thread, read by main after the matching event.
static bool g_bLegitAfterReg   = false;
static bool g_bGhostAfterReg   = false;
static bool g_bLegitBeforeClose= false;
static bool g_bGhostBeforeClose= false;
static bool g_bLegitAfterClose = false;
static bool g_bGhostAfterClose = false;

// Bumped on the CLIENT hub thread, read by main after g_hHubStat.
static volatile LONG g_nHubStatRx = 0;

static std::wstring g_strXCid;      // "CEX.XC0"        — assigned at LoginAck
static std::wstring g_strGhost;     // "CEX.XC0.Ghost"  — fabricated from it

static void Log(const char* msg)
{
    std::printf("[expreg] %s\n", msg);
    std::fflush(stdout);
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

// ---------------------------------------------------------------------------
// Registry inspection. Both callers run on the expump thread, which is the
// only thread that inserts into or removes from these lists.
// ---------------------------------------------------------------------------
static bool RegHas(CListRegHubs& oList, const std::wstring& strWant)
{
    if (strWant.empty()) return false;
    CStringADDR strKey = strWant.c_str();
    POSITION pos = oList.GetHeadPosition();
    while (pos)
    {
        SP2PexpRegHub& oReg = oList.GetNext(pos);
        if (strKey.CompareNoCase(oReg.strClient) == 0)
            return true;
    }
    return false;
}

static void DumpReg(CListRegHubs& oList, const char* pszWhen)
{
    int n = 0;
    std::printf("[expreg] m_oCListRegHubs %s:\n", pszWhen);
    POSITION pos = oList.GetHeadPosition();
    while (pos)
    {
        SP2PexpRegHub& oReg = oList.GetNext(pos);
        std::printf("[expreg]   [%d] '%s'\n", n++, N(oReg.strClient.GetString()).c_str());
    }
    if (!n) std::printf("[expreg]   <empty>\n");
    std::fflush(stdout);
}

// =========================================================================
// The Explorer under test. It overrides nothing that decides anything — both
// overrides delegate to the base first and then sample the registry the base
// just mutated. It is handed to P2PeerExpump_ACTIVATE, which spawns it,
// registers it with the hub and owns the failure paths.
// =========================================================================
class ProbeExplorer : public P2PeerExplorer
{
public:
    ProbeExplorer(P2PeerHub* pHub) : P2PeerExplorer(pHub), m_bBroadcastDone(false)
    {
        // RenderExplorerSafe() defaults this to 32; pinned here only so the
        // slot the client is assigned is predictable in the log.
        m_nMaxECid = kMaxECid;
    }
    virtual ~ProbeExplorer() {}

protected:
    virtual msgRESULT On_P2PexpCtrl(P2PeerMsg* pMsg) override
    {
        // Copy the claimed source BEFORE delegating: the base may swap the
        // message to another context, after which pMsg is not ours to read.
        std::wstring strSource;
        if (pMsg && pMsg->GetSource())
            strSource = pMsg->GetSource();

        msgRESULT msgResult = P2PeerExplorer::On_P2PexpCtrl(pMsg);
        if (msgResult != msgHANDLED)
            return msgResult;              // swapped away; we will see it again

        std::printf("[expreg] EXPLORER processed a P2PexpumpCtrl claiming source '%s'\n",
                    N(strSource.c_str()).c_str());
        DumpReg(m_oCListRegHubs, "registration");

        if (!g_strGhost.empty() && strSource == g_strGhost)
        {
            g_bGhostAfterReg = RegHas(m_oCListRegHubs, g_strGhost);
            if (g_hRegGhost) SetEvent(g_hRegGhost);
        }
        else if (!g_strXCid.empty() && strSource == g_strXCid)
        {
            g_bLegitAfterReg = RegHas(m_oCListRegHubs, g_strXCid);

            // Ask for the BROADCAST, once. QueryP2PmsgExp_Hub() with no
            // destination posts an UNADDRESSED P2PexpumpHub into this expump,
            // which is the only thing in the tree that reaches the broadcast
            // half of On_P2PmsgExp_Hub — nothing in Targetcore raises a hub
            // status change of its own (m_dwExpumpMask, P2Pwin32.cpp:1137, is
            // written and never read). Legal here and nowhere else: we are on
            // the expump thread.
            if (!m_bBroadcastDone)
            {
                m_bBroadcastDone = true;
                Log("EXPLORER broadcasting hub status to every registered sink");
                QueryP2PmsgExp_Hub(L"", FALSE);
            }
            if (g_hRegLegit) SetEvent(g_hRegLegit);
        }
        return msgResult;
    }

    virtual conRESULT On_XCidConClose(P2PeerCon* pCon) override
    {
        // The Explorer service connection closes at shutdown too; only the
        // accepted slot connection is the subject here.
        bool bOurs = false;
        if (pCon && !g_strXCid.empty())
            bOurs = (pCon->GetP2Paddress() == (P2PaddrSTR)g_strXCid.c_str());

        if (bOurs)
        {
            g_bLegitBeforeClose = RegHas(m_oCListRegHubs, g_strXCid);
            g_bGhostBeforeClose = RegHas(m_oCListRegHubs, g_strGhost);
            DumpReg(m_oCListRegHubs, "immediately BEFORE the reaper runs");
        }

        conRESULT conResult = P2PeerExplorer::On_XCidConClose(pCon);

        if (bOurs)
        {
            g_bLegitAfterClose = RegHas(m_oCListRegHubs, g_strXCid);
            g_bGhostAfterClose = RegHas(m_oCListRegHubs, g_strGhost);
            DumpReg(m_oCListRegHubs, "immediately AFTER the reaper ran");
            if (g_hClosed) SetEvent(g_hClosed);
        }
        return conResult;
    }

private:
    bool m_bBroadcastDone;
};

// =========================================================================
// The client. It holds no address of its own; the Explorer gives it one.
// =========================================================================
class ExpClientHub : public P2PeerHub
{
public:
    ExpClientHub(P2PaddrSTR strAddr) : P2PeerHub(strAddr) {}
    virtual ~ExpClientHub() {}

    // Driven from main() so the honest registration is seen to land before the
    // forged one is even sent.
    void RegisterAs(const std::wstring& strSource)
    {
        P2PeerMsg* pMsg = new P2PeerMsg(MSG_P2PexpCtrl);
        pMsg->SetSource(strSource.c_str());
        pMsg->SetDestin(kHubAddr);
        // One RHub field: "register me as a hub-status sink". The Explorer's
        // command loop walks the data node, so the message needs at least one.
        P3PmsgField_SERIALISE(pMsg->r_datn(), L"RHub", L"1",
                              FALSE, _T("p2p_expreg registration probe"));
        PostP2PeerMsg(pMsg);

        std::printf("[expreg] client posted a P2PexpumpCtrl/RHub sourced '%s'\n",
                    N(strSource.c_str()).c_str());
        std::fflush(stdout);
    }

protected:
    // The delivery assertion. The pump calls PeekP2PeerMsg() ahead of the map
    // dispatch for any message whose destination IS this hub (P2Pwin32.cpp:
    // 3112-3115) — after the LoginAck this hub IS CEX.XC0 — so this sees every
    // hub-status message the Explorer sends here. Consuming it (msgHANDLED)
    // matters: an unhandled message is reflected as an exception, which
    // On_P2PmsgExp_CATCH would treat as a dead sink and de-register.
    virtual msgRESULT PeekP2PeerMsg(P2PeerMsg* pMsg) override
    {
        if (pMsg && pMsg->Map_MatchName(MSG_P2PexpHub))
        {
            LONG n = InterlockedIncrement(&g_nHubStatRx);
            std::printf("[expreg] CLIENT received hub status #%ld: [%s] -> [%s]\n",
                        (long)n, N(pMsg->GetSource()).c_str(),
                        N(pMsg->GetDestin()).c_str());
            std::fflush(stdout);
            if (g_hHubStat) SetEvent(g_hHubStat);
            return msgHANDLED;
        }
        return P2PeerHub::PeekP2PeerMsg(pMsg);
    }

    virtual conRESULT On_ConLoginAck(P2PeerCon*  pCon,
                                     P2PaddrSTR  strThisP2Paddr,
                                     P2PaddrSTR  strThatP2Paddr,
                                     const void* pvLoginAck,
                                     P2Psize_t   iSize) override
    {
        // NOT delegated to the base on purpose. P2PeerTarget::On_ConLoginAck
        // (P2PeerTarget.cpp:2552-2557) THROWS on a non-empty acknowledgement,
        // and On_XCidConLogin acknowledges with the slot index
        // (P2PeerExplorer.cpp:1305), so the stock handler cannot complete an
        // Explorer login at all. This does what the base does minus that check.
        std::printf("[expreg] client login acknowledged: this='%s' that='%s'"
                    " (ack %d bytes)\n",
                    N(strThisP2Paddr).c_str(), N(strThatP2Paddr).c_str(), (int)iSize);
        std::fflush(stdout);
        (void)pvLoginAck;

        pCon->OnLoginAck(strThisP2Paddr, strThatP2Paddr);

        if (g_strXCid.empty() && strThisP2Paddr && *strThisP2Paddr)
        {
            g_strXCid  = strThisP2Paddr;
            g_strGhost = g_strXCid + kGhostLeaf;
            if (g_hXCid) SetEvent(g_hXCid);
        }
        return conHANDLED;
    }
};

// =========================================================================
int main(int argc, char* argv[])
{
    short nPort = (argc >= 2) ? (short)atoi(argv[1]) : 7819;

    std::printf("=== p2p_expreg — Explorer registration: forgery, reaping, delivery ===\n");
    std::printf("Port : %d\n", (int)nPort);
    std::printf("Asserting: only an identity the Explorer assigned may register,\n"
                "           everything under it is released when it drops, and\n"
                "           hub status reaches the sink that registered for it.\n\n");
    std::fflush(stdout);

    g_hXCid     = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hRegLegit = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hRegGhost = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hClosed   = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hHubStat  = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16)) { Log("SETUP: StartupP2Pmsg() failed"); return 2; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);

    int nExit = 2;
    {
        P2PeerHub    oServer(kHubAddr);
        ExpClientHub oClient(kAnonAddr);

        //  RequireAuth(false) on both hubs. The registration expiry under test is
        //  explicitly NOT conditioned on RequireAuth (see the header note): it keys
        //  on ConState_Login alone. Requiring auth here - the default since Stage 3
        //  step 8 - would add a second reason for the anonymous client to be
        //  refused and make a pass unattributable.
        oServer.RequireAuth ( false );
        oClient.RequireAuth ( false );
        HANDLE hServerThread = oServer.SpawnHub();
        if (!hServerThread) { Log("SETUP: server SpawnHub() failed"); return 2; }

        // ---- Phase 0: stand the Explorer up through the LIBRARY -------------
        ProbeExplorer *pExp = 0;
        try
        {
            pExp = new ProbeExplorer(&oServer);
            P2PeerExpump *pActive = P2PeerExpump_ACTIVATE(&oServer, pExp);
            if (!pActive)
            { Log("SETUP: P2PeerExpump_ACTIVATE() failed"); return 2; }
            if (pActive != pExp)
            { Log("SETUP: ACTIVATE did not adopt the supplied instance"); return 2; }
            if (oServer.GetP2PeerExpump() != pExp)
            {
                Log("SETUP: ACTIVATE left the hub with no expump — nothing can"
                    " route to the Explorer (P2PeerHub::PostP2PeerExpump)");
                return 2;
            }
            // The already-exists guard: a second activation must hand back the
            // incumbent and dispose of the candidate, never replace or strand.
            if (P2PeerExpump_ACTIVATE(&oServer) != pExp ||
                oServer.GetP2PeerExpump()       != pExp)
            { Log("SETUP: a second ACTIVATE displaced the incumbent expump"); return 2; }
        }
        catch (P2Pevent* pEVT)
        {
            pEVT->Advice(_T("p2p_expreg: could not stand up the Explorer"))->Cancel();
            Log("SETUP: Explorer activation threw");
            return 2;
        }
        Log("Explorer expump activated and registered with the server hub");

        P2PeerConWsa* pSvc = P2PeerConWsa::ServiceFactory(kExpDomain, nPort);
        if (!pSvc) { Log("SETUP: ServiceFactory failed"); return 2; }
        if (pExp->PostP2PeerCon(pSvc))
        { Log("SETUP: PostP2PeerCon() to the expump failed"); return 2; }
        Log("Explorer service listening — slots handed out as CEX.XC%i");

        Sleep(500);   // let the listener bind before dialling

        HANDLE hClientThread = oClient.SpawnHub();
        if (!hClientThread) { Log("SETUP: client SpawnHub() failed"); return 2; }

        P2PeerConWsa* pCli = P2PeerConWsa::ClientFactory(kHubAddr, L"127.0.0.1", nPort);
        if (!pCli) { Log("SETUP: ClientFactory failed"); return 2; }
        oClient.PostP2PeerCon(pCli);
        Log("anonymous client dialling — it declares no address of its own");

        bool bArmAfail = false;      // fabricated descendant registered
        bool bArmBfail = false;      // it survived the disconnect
        bool bArmBmoot = false;      // could not be judged

        // ---- Phase 1: the Explorer must assign us a slot -------------------
        if (WaitForSingleObject(g_hXCid, 15000) != WAIT_OBJECT_0)
        {
            std::printf(
              "\nRESULT: INCONCLUSIVE — the Explorer never assigned an XCid, so\n"
              "  the registration path was never reached and neither residual\n"
              "  could be measured. This is NOT a pass.\n"
              "  Look for \"No free ECid exploration slots available\" or a\n"
              "  \"Null P2Paddr expected\" rejection above (P2PeerExplorer.cpp:1279,\n"
              "  :1296). Check wsa_mesh first; if that is red, fix that first.\n");
            nExit = 3;
        }
        else
        {
            std::printf("[expreg] the Explorer assigned this peer '%s'\n",
                        N(g_strXCid.c_str()).c_str());
            std::fflush(stdout);

            // ---- Phase 2: the positive control must land -------------------
            Log("--- phase 2: HONEST registration, sourced as the assigned slot ---");
            oClient.RegisterAs(g_strXCid);

            if (WaitForSingleObject(g_hRegLegit, 10000) != WAIT_OBJECT_0 ||
                !g_bLegitAfterReg)
            {
                std::printf(
                  "\nRESULT: INCONCLUSIVE — the HONEST registration never reached\n"
                  "  the Explorer registry, so a refusal of the forged one would\n"
                  "  prove nothing. This is NOT a pass.\n");
                nExit = 3;
            }
            else
            {
                Log("positive control OK — the honest registration is in the registry");

                // ---- Phase 2b: it must actually be answered AND broadcast to
                // Two P2PexpumpHub's are owed to CEX.XC0 for that one RHub: the
                // addressed answer the base handler emits, and the redirected
                // broadcast the ProbeExplorer then asks for. No further
                // registration has been sent, so nothing else can produce one.
                Log("--- phase 2b: the Explorer's hub status must reach the sink ---");
                for (int i = 0; i < 20 &&
                                InterlockedExchangeAdd(&g_nHubStatRx, 0) < 2; ++i)
                    WaitForSingleObject(g_hHubStat, 500);

                LONG nRx = InterlockedExchangeAdd(&g_nHubStatRx, 0);
                if (nRx < 2)
                {
                    std::printf(
                      "\nRESULT: INCONCLUSIVE — the Explorer registered the sink\n"
                      "  and then failed to deliver to it: %ld of the 2 owed\n"
                      "  P2PexpumpHub messages reached '%s' while the peer was\n"
                      "  still connected. A directory service that cannot answer\n"
                      "  is not a pass; the registry result below is moot.\n"
                      "  Look for \"Message[P2PexpumpHub] ... not deliverable\"\n"
                      "  (P2PeerTarget::RouteP2PeerMsg, P2PeerTarget.cpp:1468) and\n"
                      "  for the connection lookup in P2PeerExplorer::RouteP2PeerMsg\n"
                      "  (P2PeerExplorer.cpp:705).\n",
                      (long)nRx, N(g_strXCid.c_str()).c_str());
                    nExit = 3;
                }
                else
                {
                std::printf("[expreg] delivery OK — %ld hub-status messages"
                            " reached the sink\n", (long)nRx);
                std::fflush(stdout);

                // ---- Phase 3: arm (a), the forgery -------------------------
                Log("--- phase 3: FORGED registration, sourced as a sub-identity "
                    "the Explorer never assigned ---");
                oClient.RegisterAs(g_strGhost);

                if (WaitForSingleObject(g_hRegGhost, 8000) == WAIT_OBJECT_0 &&
                    g_bGhostAfterReg)
                {
                    std::printf(
                      "[expreg] ARM (a) FAILED — '%s' is in the registry.\n",
                      N(g_strGhost.c_str()).c_str());
                    bArmAfail = true;
                }
                else
                {
                    Log("ARM (a) passed — the fabricated descendant was refused");
                }
                std::fflush(stdout);

                // ---- Phase 4: arm (b), the reaping -------------------------
                Log("--- phase 4: the peer disconnects; On_XCidConClose must "
                    "release everything under its slot ---");
                oClient.CloseHub();
                WaitForSingleObject(hClientThread, 5000);

                if (WaitForSingleObject(g_hClosed, 10000) != WAIT_OBJECT_0)
                {
                    std::printf(
                      "[expreg] ARM (b) INCONCLUSIVE — On_XCidConClose never ran\n"
                      "  for '%s', so nothing about reaping was observed.\n",
                      N(g_strXCid.c_str()).c_str());
                    bArmBmoot = true;
                }
                else if (g_bLegitAfterClose)
                {
                    std::printf(
                      "[expreg] ARM (b) INCONCLUSIVE — the reaper ran and did not\n"
                      "  even remove the LEGITIMATE entry '%s'. Reaping is broken\n"
                      "  outright, so the stale-descendant question is not what\n"
                      "  this run measured.\n", N(g_strXCid.c_str()).c_str());
                    bArmBmoot = true;
                }
                else if (!bArmAfail || !g_bGhostBeforeClose)
                {
                    std::printf(
                      "[expreg] ARM (b) not applicable — no fabricated entry was\n"
                      "  present when the connection dropped.\n");
                }
                else if (g_bGhostAfterClose)
                {
                    std::printf(
                      "[expreg] ARM (b) FAILED — '%s' survived the disconnect.\n",
                      N(g_strGhost.c_str()).c_str());
                    bArmBfail = true;
                }
                else
                {
                    Log("ARM (b) passed — the fabricated entry went with the slot");
                }
                std::fflush(stdout);

                // ---- Verdict ------------------------------------------------
                if (bArmAfail || bArmBfail)
                {
                    std::printf(
                      "\nRESULT: FAIL — EXPLORER REGISTRATION IS NOT BOUND TO THE\n"
                      "  ASSIGNED IDENTITY.\n");
                    if (bArmAfail)
                      std::printf(
                      "  (a) The peer held '%s' — an address it did not choose and\n"
                      "      could not choose — and still registered '%s', a\n"
                      "      sub-identity the Explorer never assigned and nobody\n"
                      "      holds. The source-binding gate passed it because\n"
                      "      IsRable() accepts hop-boundary descendants\n"
                      "      (P2Peer.cpp:365-377, P2PeerCon.cpp:2058), and\n"
                      "      On_P2PexpCtrl registered pMsg->GetSource() as it found\n"
                      "      it (P2PeerExplorer.cpp:1424,1439).\n",
                      N(g_strXCid.c_str()).c_str(), N(g_strGhost.c_str()).c_str());
                    if (bArmBfail)
                      std::printf(
                      "  (b) It then survived the disconnect. On_XCidConClose\n"
                      "      reaped by the EXACT slot address, not by prefix, and\n"
                      "      the registry has no other eviction path — so every\n"
                      "      fabricated entry is permanent. Unbounded growth, and\n"
                      "      a broadcast list that keeps redirecting to addresses\n"
                      "      nobody holds.\n");
                    std::printf(
                      "  Fix: assign registrations from the CONNECTION's identity,\n"
                      "  not the message's, and reap by prefix. See\n"
                      "  Ahtung_Disaster.md Part 3 (M2, Explorer) and SECURITY.md.\n");
                    nExit = 1;
                }
                else if (bArmBmoot)
                {
                    std::printf(
                      "\nRESULT: INCONCLUSIVE — the forgery arm passed but the\n"
                      "  reaping arm could not be judged (see above). NOT a pass.\n");
                    nExit = 3;
                }
                else
                {
                    std::printf(
                      "\nRESULT: PASS — Explorer registration is bound to the\n"
                      "  assigned identity, and the service answers.\n"
                      "  Stood up through P2PeerExpump_ACTIVATE and registered with\n"
                      "  the hub; the honest registration ('%s') landed, was\n"
                      "  answered and broadcast to, and was released on\n"
                      "  disconnect; the fabricated descendant ('%s') was refused.\n",
                      N(g_strXCid.c_str()).c_str(), N(g_strGhost.c_str()).c_str());
                    nExit = 0;
                }
                }
            }
        }

        Log("shutdown begin");
        try { oClient.CloseHub(); } catch (P2Pevent* pEVT) { pEVT->Cancel(); }
        WaitForSingleObject(hClientThread, 3000);
        CloseHandle(hClientThread);

        // Stop the expump in ITS OWN context first. That is the documented
        // order for a SPECIALISED expump and not a workaround: the base
        // destructor will wait for the pump too, but by then ~ProbeExplorer has
        // already run and the pump thread would be calling overrides on a
        // half-destroyed object. The hub then DELETES it (CloseHub ->
        // DropP2PeerExpump), which is the whole point — ~P2PeerExplorer used to
        // throw out of that delete, from this very thread.
        try { if (pExp) pExp->CloseExpump(0); }
        catch (P2Pevent* pEVT) { pEVT->Advice(_T("p2p_expreg: CloseExpump"))->Cancel(); }

        try { oServer.CloseHub(); } catch (P2Pevent* pEVT) { pEVT->Cancel(); }
        WaitForSingleObject(hServerThread, 3000);
        CloseHandle(hServerThread);

        if (oServer.GetP2PeerExpump())
            Log("WARNING: the hub still holds an expump pointer after CloseHub()");
    }

    CleanupP2Pmsg();
    if (g_hXCid)     { CloseHandle(g_hXCid);     g_hXCid     = NULL; }
    if (g_hRegLegit) { CloseHandle(g_hRegLegit); g_hRegLegit = NULL; }
    if (g_hRegGhost) { CloseHandle(g_hRegGhost); g_hRegGhost = NULL; }
    if (g_hClosed)   { CloseHandle(g_hClosed);   g_hClosed   = NULL; }
    if (g_hHubStat)  { CloseHandle(g_hHubStat);  g_hHubStat  = NULL; }
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
