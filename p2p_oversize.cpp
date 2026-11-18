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
// p2p_oversize.cpp — an outbound message whose FRAME is over the send limit is
// refused and reported to its sender, and the LINK STAYS UP. F-P0-15.
//
// ---------------------------------------------------------------------------
// THE DEFECT (measured 2026-11-18, p2p_performance_progress.md F-P0-15)
//
//   A message goes on the wire as its whole image: payload + ~2,082 bytes of
//   its own structure (F-P0-16), plus the link cypher's nonce and tag when one
//   is installed. The receiver refuses any frame over its m_dwMaxRecvSize
//   (32,768) in P2Peerio::RecvP2PeerMsg - and refusing it there means THROWING
//   on the receive path, which DROPS THE CONNECTION. The send side had a
//   matching m_dwMaxSendSize that nothing ever read. So:
//
//       payload 30,600 B  -> frame 32,682  delivered
//       payload 30,700 B  -> frame 32,782  "Attempt to exceed maximum (32768)
//                                           buffer size (32782)", link dropped
//
//   and the poster was told nothing. Every message queued behind it on the
//   link was lost too. The usable maximum was a number no application could
//   know: MAX_P2Psize minus a slack M1 will change, minus the cypher's growth.
//
// THE FIX
//
//   P2Peerio::SendP2PeerMsg measures the frame it is about to write, cypher
//   growth included, before running the cypher, and over the limit writes
//   nothing and returns kSendRefusedFrame. P2PeerCon's send path then refuses
//   the MESSAGE (RefuseOversizedOutbound: diagnostic + a P2Pevent_UNDELIVERABLE
//   report to the source), keeps the link, and takes the next message off the
//   queue. Transports that frame their own bytes override SendP2PeerMsg and are
//   untouched by design (p2pweb_w12 is the guard on that).
//
// WHAT IT DOES — two hubs on one socket, the leaf posts to its parent.
//
//   Run twice, once per link mode, because the two modes put the limit in
//   different places and a fix that forgot the cypher would pass the first:
//
//     PLAIN   RequireAuth(false), no cypher. 30,600 B delivered (control);
//             31,000 B must be refused and reported, link up; 64 B after it
//             must arrive.
//     CYPHER  RequireAuth(true) with keys, so the link runs the key agreement
//             and installs the session cypher (checked, not assumed). 30,600 B
//             delivered (control); 30,680 B - whose PLAIN frame is 32,762 and
//             fits, but whose cyphered frame does not - must be refused and
//             reported, link up; 64 B after it must arrive.
//
// VERDICT = process EXIT CODE:
//   0  PASS          both modes: refused, reported, link kept
//   1  FAIL          a mode dropped the link, delivered the oversized message,
//                    sent no report, or lost the message after it
//   2  SETUP         startup / factory / key provisioning failure
//   3  INCONCLUSIVE  a control did not arrive, or CYPHER mode did not get a
//                    cypher - then the refusal proves nothing. NOT a pass

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "P2PIdentityStore.h"
#include "Msgexception.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#  include <crtdbg.h>          // headless assert trap - a dialog would hang ctest
#endif

// ---------------------------------------------------------------------------
static std::atomic<long> g_nDelivered{0};      // BCasts the ROOT delivered
static std::atomic<long> g_nLastBytes{0};      // body length of the last one
static std::atomic<long> g_nReports{0};        // reports the LEAF received
static std::atomic<bool> g_bClosed{false};     // the LEAF's link went down
static std::atomic<bool> g_bLoginAck{false};
static std::atomic<int>  g_nCypher{-1};        // the leaf's link, at its login ack

static void Log(const char* msg) { std::printf("[oversize] %s\n", msg); std::fflush(stdout); }

#ifdef _WIN32
static int __cdecl AssertReportHook(int nReportType, char* szMsg, int* pnRet)
{
    if (nReportType == _CRT_ASSERT)
    {
        std::fflush(stdout);
        std::fprintf(stderr, "[oversize] ASSERT: %s", szMsg ? szMsg : "(none)");
        std::fflush(stderr);
        if (pnRet) *pnRet = 0;
        return TRUE;
    }
    return FALSE;
}
#endif
static void OnTerminate()
{
    std::fflush(stdout);
    std::fprintf(stderr, "[oversize] TERMINATE - an exception escaped a thread\n");
    std::fflush(stderr);
    std::abort();
}

// --- keys for CYPHER mode, temp files deleted at exit (as perf_ab) ---------
static std::vector<std::string> g_vTemp;
static std::string TempPath(const char* leaf)
{
    char dir[MAX_PATH + 2] = {0};
    DWORD n = GetTempPathA(MAX_PATH + 1, dir);
    std::string s = (n > 0 && n <= MAX_PATH) ? std::string(dir) : std::string(".\\");
    char pid[32]; std::snprintf(pid, sizeof pid, "%lu", (unsigned long)GetCurrentProcessId());
    s += "p2p_oversize_"; s += leaf; s += "_"; s += pid; s += ".tmp";
    DeleteFileA(s.c_str());
    g_vTemp.push_back(s);
    return s;
}
static void ScrubTemp() { for (auto& s : g_vTemp) DeleteFileA(s.c_str()); g_vTemp.clear(); }

struct Keys { std::string key, acl; };
static bool Provision(const char* rootName, const char* leafName, Keys& root, Keys& leaf)
{
    root.key = TempPath("rootkey"); root.acl = TempPath("rootacl");
    leaf.key = TempPath("leafkey"); leaf.acl = TempPath("leafacl");
    unsigned char idR[p2pcng::kEcdsaPubLen], idL[p2pcng::kEcdsaPubLen];
    auto ident = [](const std::string& p, unsigned char* pub) {
        p2pcng::EcdsaP256 k;
        return k.Generate() && p2pcng::SaveIdentity(p.c_str(), k) == p2pcng::IdOk && k.ExportPublic(pub); };
    if (!ident(root.key, idR) || !ident(leaf.key, idL)) return false;
    return p2pcng::AppendAllowList(root.acl.c_str(), leafName, idL, nullptr) == p2pcng::IdOk
        && p2pcng::AppendAllowList(leaf.acl.c_str(), rootName, idR, nullptr) == p2pcng::IdOk;
}

// =========================================================================
class OverHub : public P2PeerHub
{
public:
    OverHub(P2PaddrSTR strAddr, bool bRoot) : P2PeerHub(strAddr), m_bRoot(bRoot) {}
    virtual ~OverHub() {}

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        if (m_bRoot && pMsg)
        {
            g_nLastBytes = (long)pMsg->DataSize();
            g_nDelivered.fetch_add(1);
        }
        return msgHANDLED;
    }
    // A report wrapping a BCast is dispatched on the WRAPPED name, so it lands
    // in On_MsgCatch, not in the P2Pmsg_Exception entry - both are counted
    // (p2p_bigreport records the same detail).
    virtual msgRESULT On_MsgCatch(P2PeerMsg* pMsg) override
    {
        if (!m_bRoot) g_nReports.fetch_add(1);
        return P2PeerHub::On_MsgCatch(pMsg);
    }
    virtual msgRESULT On_MsgCatchCatch(P2PeerMsg* pMsg) override
    {
        if (!m_bRoot) g_nReports.fetch_add(1);
        return P2PeerHub::On_MsgCatchCatch(pMsg);
    }
    virtual conRESULT On_ConLoginAck(P2PeerCon* pCon, P2PaddrSTR a, P2PaddrSTR b,
                                     const void* p, P2Psize_t n) override
    {
        conRESULT r = P2PeerHub::On_ConLoginAck(pCon, a, b, p, n);
        if (!m_bRoot)
        {
            if (pCon) g_nCypher = pCon->IsCypherActive() ? 1 : 0;
            g_bLoginAck = true;
        }
        return r;
    }
    virtual conRESULT On_ConClose(P2PeerCon* pCon) override
    {
        if (!m_bRoot) g_bClosed = true;
        return P2PeerHub::On_ConClose(pCon);
    }
private:
    bool m_bRoot;
};

template <class F> static bool WaitFor(F pred, int ms)
{
    auto t0 = std::chrono::steady_clock::now();
    while (!pred())
    {
        if (std::chrono::steady_clock::now() - t0 > std::chrono::milliseconds(ms)) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}

static void PostBytes(OverHub& leaf, P2PaddrSTR src, P2PaddrSTR dst, int nBytes)
{
    std::vector<char> v((size_t)nBytes, 'A');
    leaf.PostP2PeerMsg(new P2PeerMsg32(src, dst, P2Pmsg_BCast, &v[0], (P2Psize_t)nBytes));
}

// One mode. Returns the exit code for it.
static int RunMode(bool bCypher, short nPort)
{
    const P2PaddrSTR kRoot = bCypher ? L"OverC"      : L"OverP";
    const P2PaddrSTR kLeaf = bCypher ? L"OverC.Leaf" : L"OverP.Leaf";
    const char* tag = bCypher ? "CYPHER" : "PLAIN";
    const int kControl = 30600;
    const int kOver    = bCypher ? 30680 : 31000;   // see the header for why

    std::printf("\n--- mode %s, port %d: control %d B, oversized %d B ---\n",
                tag, (int)nPort, kControl, kOver);
    std::fflush(stdout);
    g_nDelivered = 0; g_nReports = 0; g_bClosed = false; g_bLoginAck = false; g_nCypher = -1;

    Keys kr, kl;
    if (bCypher && !Provision("OverC", "OverC.Leaf", kr, kl)) { Log("SETUP: key provisioning failed"); return 2; }

    int nExit = 2;
    OverHub oRoot(kRoot, true), oLeaf(kLeaf, false);
    for (OverHub* h : { &oRoot, &oLeaf })
    {
        // The limit is a property of the link, not of these policies: seal,
        // attestation and revocation are off so the frame is exactly the
        // message, and CYPHER differs from PLAIN by the session cypher only.
        h->RequireAuth(bCypher);
        h->RequireRelayAuth(false);
        h->RequireSeal(false);
        h->RequireRevocation(false);
    }
    if (bCypher &&
        (oRoot.SetIdentity(kr.key.c_str()) != p2pcng::IdOk || oRoot.SetAllowList(kr.acl.c_str()) != p2pcng::IdOk ||
         oLeaf.SetIdentity(kl.key.c_str()) != p2pcng::IdOk || oLeaf.SetAllowList(kl.acl.c_str()) != p2pcng::IdOk))
    { Log("SETUP: SetIdentity/SetAllowList failed"); return 2; }

    HANDLE hR = oRoot.SpawnHub(), hL = oLeaf.SpawnHub();
    if (!hR || !hL) { Log("SETUP: SpawnHub failed"); return 2; }
    P2PeerConWsa* pSvc = P2PeerConWsa::ServiceFactory(kLeaf, nPort);
    if (!pSvc) { Log("SETUP: ServiceFactory failed"); return 2; }
    oRoot.PostP2PeerCon(pSvc);
    Sleep(500);
    P2PeerConWsa* pCli = P2PeerConWsa::ClientFactory(kRoot, L"127.0.0.1", nPort);
    if (!pCli) { Log("SETUP: ClientFactory failed"); return 2; }
    oLeaf.PostP2PeerCon(pCli);

    if (!WaitFor([] { return g_bLoginAck.load(); }, 15000))
        { std::printf("[oversize] %s: SETUP - no login ack\n", tag); nExit = 2; }
    else if (bCypher && g_nCypher.load() != 1)
        { std::printf("[oversize] %s: INCONCLUSIVE - the link has no session cypher (cypher=%d),\n"
                      "  so the cyphered-frame limit is not under test\n", tag, g_nCypher.load()); nExit = 3; }
    else
    {
        std::printf("[oversize] %s: link up, cypher=%d\n", tag, g_nCypher.load());
        // ---- 1. CONTROL: the largest payload that fits is delivered ------
        PostBytes(oLeaf, kLeaf, kRoot, kControl);
        if (!WaitFor([] { return g_nDelivered.load() >= 1; }, 10000) || g_nLastBytes.load() != kControl)
        {
            std::printf("[oversize] %s: INCONCLUSIVE - the %d-byte control was not delivered\n"
                        "  (delivered=%ld closed=%d), so a refusal below would prove nothing\n",
                        tag, kControl, g_nDelivered.load(), (int)g_bClosed.load());
            nExit = 3;
        }
        else
        {
            // ---- 2. the oversized message, then a small one behind it ----
            PostBytes(oLeaf, kLeaf, kRoot, kOver);
            PostBytes(oLeaf, kLeaf, kRoot, 64);
            bool bAfter  = WaitFor([] { return g_nDelivered.load() >= 2; }, 10000);
            bool bReport = WaitFor([] { return g_nReports.load() >= 1; }, 5000);
            Sleep(300);   // anything late - a second delivery, a close - lands now
            const long nDel = g_nDelivered.load();
            const bool bClosed = g_bClosed.load();
            std::printf("[oversize] %s: delivered=%ld (want 2) last=%ld B (want 64) reports=%ld closed=%d\n",
                        tag, nDel, g_nLastBytes.load(), g_nReports.load(), (int)bClosed);
            if (bClosed)
                std::printf("[oversize] %s: FAIL - the LINK was dropped. The receiver refused the\n"
                            "  oversized frame and tore the connection down (F-P0-15)\n", tag);
            else if (nDel > 2 || (bAfter && g_nLastBytes.load() != 64))
                std::printf("[oversize] %s: FAIL - the %d-byte message was delivered; it should not fit\n", tag, kOver);
            else if (!bAfter)
                std::printf("[oversize] %s: FAIL - the 64-byte message after the refused one never arrived\n", tag);
            else if (!bReport)
                std::printf("[oversize] %s: FAIL - refused, but the sender was not told: no report\n", tag);
            else
            {
                std::printf("[oversize] %s: PASS - refused, reported, link kept, next message delivered\n", tag);
                nExit = 0;
            }
            if (nExit != 0 && nExit != 3) nExit = 1;
        }
    }

    oLeaf.CloseHub();
    oRoot.CloseHub();
    WaitForSingleObject(hL, 3000);
    WaitForSingleObject(hR, 3000);
    CloseHandle(hL); CloseHandle(hR);
    return nExit;
}

int main(int argc, char* argv[])
{
    short nPortPlain  = (argc >= 2) ? (short)std::atoi(argv[1]) : 7822;
    short nPortCypher = (argc >= 3) ? (short)std::atoi(argv[2]) : 7825;

    std::printf("=== p2p_oversize - an oversized frame refuses the message, not the link (F-P0-15) ===\n");
    std::fflush(stdout);
#ifdef _WIN32
    _CrtSetReportHook(AssertReportHook);
#endif
    std::set_terminate(OnTerminate);

    if (!StartupP2Pmsg(16)) { Log("SETUP: StartupP2Pmsg() failed"); return 2; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);

    int nPlain  = RunMode(false, nPortPlain);
    int nCypher = RunMode(true,  nPortCypher);

    CleanupP2Pmsg();
    WSACleanup();
    ScrubTemp();

    // Worst verdict wins: FAIL over INCONCLUSIVE over SETUP over PASS.
    auto rank = [](int v) { return v == 1 ? 3 : v == 3 ? 2 : v == 2 ? 1 : 0; };
    int nExit = rank(nPlain) >= rank(nCypher) ? nPlain : nCypher;
    std::printf("\nRESULT: plain=%d cypher=%d -> exit %d\n", nPlain, nCypher, nExit);
    std::fflush(stdout);
    return nExit;
}
