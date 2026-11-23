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
// p2p_sendgather.cpp — a BURST on one link arrives whole and IN ORDER when the
// send path gathers it into one write (MSCS performance plan T3).
//
// ---------------------------------------------------------------------------
// WHAT IS UNDER TEST
//
//   Until T3 a connection wrote one frame per transport write. Since T3 the
//   send completion on the stock transport (P2Peerio: TCP, pipe, serial)
//   stages every queued message it can - each still trimmed, measured against
//   the frame cap and sealed by the link cypher on its own - and writes up to
//   64 frames or 64 KB with ONE write (Targetcore P2Peerio.h,
//   P2PeerioSendGather). What that can get wrong, and what this checks:
//
//     * ORDER - frames gathered out of queue order, or one dropped or doubled
//       at a batch boundary. Every message carries its sequence number and the
//       receiver requires them strictly increasing with nothing missing.
//     * A REFUSED FRAME INSIDE A BATCH - an oversized message (over the 32 KB
//       frame cap) is refused and reported, and the batch goes on around it.
//       Two refusals back to back, and one right after a lone frame (the
//       frame the gather has not copied yet), are both in the burst.
//     * THE BUDGET - a 20 KB message every 50th, so batches cross the 64 KB
//       budget and the gather buffer grows.
//     * THE CYPHER - the link cypher's swap buffer is overwritten by the next
//       frame's encryption, so a gather that copied too late would send the
//       wrong bytes for one frame and the receiver would refuse to open it
//       (link dropped). Run with the session cypher on, checked not assumed.
//
//   The gather is not observable from outside except as this: if it is off
//   (P2P_SEND_GATHER=0) this test still passes - it is the CORRECTNESS gate,
//   and perf_ab / perf_fanout measure the effect.
//
// WHAT IT DOES — two hubs on one socket, the leaf bursts N messages at its
//   parent from one thread without waiting, so they queue behind the first
//   write. Two modes: PLAIN (RequireAuth(false)) and CYPHER (key agreement,
//   session cypher installed).
//
// VERDICT = process EXIT CODE:
//   0  PASS          both modes: every sendable message delivered once, in
//                    order; every oversized one refused and reported; link up
//   1  FAIL          out of order, missing, doubled, delivered-when-oversized,
//                    unreported, or the link dropped
//   2  SETUP         startup / factory / key provisioning failure
//   3  INCONCLUSIVE  no session cypher in CYPHER mode

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
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#  include <crtdbg.h>          // headless assert trap - a dialog would hang ctest
#endif

// ---------------------------------------------------------------------------
static const int kBurst     = 600;   // messages in the burst
static const int kSmall     = 64;    // body bytes of most of them
static const int kLarge     = 20000; // every kLargeEvery-th: batches cross 64 KB
static const int kLargeEvery= 50;
static bool IsOversized(int i) { return i == 100 || i == 101 || i == 351; }

static std::mutex         g_oMx;
static std::vector<int>   g_vSeq;             // sequence numbers the ROOT received
static std::atomic<long>  g_nBadBody{0};      // body did not match its sequence
static std::atomic<long>  g_nReports{0};      // reports the LEAF received
static std::atomic<bool>  g_bClosed{false};   // the LEAF's link went down
static std::atomic<bool>  g_bLoginAck{false};
static std::atomic<int>   g_nCypher{-1};

static void Log(const char* msg) { std::printf("[sendgather] %s\n", msg); std::fflush(stdout); }

#ifdef _WIN32
static int __cdecl AssertReportHook(int nReportType, char* szMsg, int* pnRet)
{
    if (nReportType == _CRT_ASSERT)
    {
        std::fflush(stdout);
        std::fprintf(stderr, "[sendgather] ASSERT: %s", szMsg ? szMsg : "(none)");
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
    std::fprintf(stderr, "[sendgather] TERMINATE - an exception escaped a thread\n");
    std::fflush(stderr);
    std::abort();
}

// --- keys for CYPHER mode, temp files deleted at exit (as p2p_oversize) ----
static std::vector<std::string> g_vTemp;
static std::string TempPath(const char* leaf)
{
    char dir[MAX_PATH + 2] = {0};
    DWORD n = GetTempPathA(MAX_PATH + 1, dir);
    std::string s = (n > 0 && n <= MAX_PATH) ? std::string(dir) : std::string(".\\");
    char pid[32]; std::snprintf(pid, sizeof pid, "%lu", (unsigned long)GetCurrentProcessId());
    s += "p2p_sendgather_"; s += leaf; s += "_"; s += pid; s += ".tmp";
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

// The body: the sequence number, then a byte pattern derived from it, so a
// frame carrying another frame's bytes is caught even if its length matches
static void FillBody(std::vector<char>& v, int nSeq)
{
    std::memcpy(&v[0], &nSeq, sizeof nSeq);
    for (size_t k = sizeof nSeq; k < v.size(); ++k)
        v[k] = (char)((nSeq * 31 + (int)k) & 0x7F);
}
static bool CheckBody(const char* p, size_t n, int* pnSeq)
{
    if (n < sizeof(int)) return false;
    std::memcpy(pnSeq, p, sizeof(int));
    for (size_t k = sizeof(int); k < n; ++k)
        if (p[k] != (char)((*pnSeq * 31 + (int)k) & 0x7F)) return false;
    return true;
}

// =========================================================================
class GatherHub : public P2PeerHub
{
public:
    GatherHub(P2PaddrSTR strAddr, bool bRoot) : P2PeerHub(strAddr), m_bRoot(bRoot) {}
    virtual ~GatherHub() {}

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        if (m_bRoot && pMsg)
        {
            int nSeq = -1;
            if (!CheckBody((const char*)pMsg->Data(), (size_t)pMsg->DataSize(), &nSeq))
                g_nBadBody.fetch_add(1);
            std::lock_guard<std::mutex> g(g_oMx);
            g_vSeq.push_back(nSeq);
        }
        return msgHANDLED;
    }
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

// The frame's overhead over its payload, measured as p2p_oversize does
static int FrameOverhead(P2PaddrSTR src, P2PaddrSTR dst)
{
    const int nProbe = 30000;
    std::vector<char> v((size_t)nProbe, 'A');
    P2PeerMsg32 oMsg(src, dst, P2Pmsg_BCast, &v[0], (P2Psize_t)nProbe);
    oMsg.TrimP2Piomage();
    oMsg.PrepareP2Piomage(~(DWORD)0);
    const int nFrame = (int)oMsg.P2PiomageSize();
    oMsg.ReleaseP2Piomage();
    return nFrame - nProbe;
}

static size_t DeliveredCount()
{
    std::lock_guard<std::mutex> g(g_oMx);
    return g_vSeq.size();
}

// One mode. Returns the exit code for it.
static int RunMode(bool bCypher, short nPort)
{
    const P2PaddrSTR kRoot = bCypher ? L"GathC"      : L"GathP";
    const P2PaddrSTR kLeaf = bCypher ? L"GathC.Leaf" : L"GathP.Leaf";
    const char* tag = bCypher ? "CYPHER" : "PLAIN";
    const int kOver = 32768 - FrameOverhead(kLeaf, kRoot) + 64;   // 64 B over the cap

    int nWant = 0, nOverCount = 0;
    for (int i = 0; i < kBurst; ++i) { if (IsOversized(i)) ++nOverCount; else ++nWant; }
    std::printf("\n--- mode %s, port %d: burst %d (%d sendable, %d oversized at %d B) ---\n",
                tag, (int)nPort, kBurst, nWant, nOverCount, kOver);
    std::fflush(stdout);
    { std::lock_guard<std::mutex> g(g_oMx); g_vSeq.clear(); }
    g_nBadBody = 0; g_nReports = 0; g_bClosed = false; g_bLoginAck = false; g_nCypher = -1;

    Keys kr, kl;
    if (bCypher && !Provision("GathC", "GathC.Leaf", kr, kl)) { Log("SETUP: key provisioning failed"); return 2; }

    int nExit = 2;
    GatherHub oRoot(kRoot, true), oLeaf(kLeaf, false);
    for (GatherHub* h : { &oRoot, &oLeaf })
    {
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
        { std::printf("[sendgather] %s: SETUP - no login ack\n", tag); nExit = 2; }
    else if (bCypher && g_nCypher.load() != 1)
        { std::printf("[sendgather] %s: INCONCLUSIVE - no session cypher (cypher=%d)\n",
                      tag, g_nCypher.load()); nExit = 3; }
    else
    {
        std::printf("[sendgather] %s: link up, cypher=%d, gather %s\n", tag, g_nCypher.load(),
                    (std::getenv("P2P_SEND_GATHER") && std::strcmp(std::getenv("P2P_SEND_GATHER"), "0") == 0)
                        ? "OFF (P2P_SEND_GATHER=0)" : "on");
        // ---- the burst: one thread, no waiting --------------------------
        for (int i = 0; i < kBurst; ++i)
        {
            const int nBytes = IsOversized(i) ? kOver : (i % kLargeEvery == 0 ? kLarge : kSmall);
            std::vector<char> v((size_t)nBytes);
            FillBody(v, i);
            oLeaf.PostP2PeerMsg(new P2PeerMsg32(kLeaf, kRoot, P2Pmsg_BCast, &v[0], (P2Psize_t)nBytes));
        }
        WaitFor([&] { return DeliveredCount() >= (size_t)nWant || g_bClosed.load(); }, 30000);
        WaitFor([&] { return g_nReports.load() >= nOverCount; }, 5000);
        Sleep(300);   // anything late - a double, a close - lands now

        std::vector<int> vSeq;
        { std::lock_guard<std::mutex> g(g_oMx); vSeq = g_vSeq; }
        int nOutOfOrder = 0, nOversizedSeen = 0, nMissing = 0, iFirstBad = -1;
        int iExpect = 0;
        for (size_t k = 0; k < vSeq.size(); ++k)
        {
            while (iExpect < kBurst && IsOversized(iExpect)) ++iExpect;
            const int s = vSeq[k];
            if (s >= 0 && s < kBurst && IsOversized(s)) ++nOversizedSeen;
            if (s != iExpect) { ++nOutOfOrder; if (iFirstBad < 0) iFirstBad = (int)k; }
            iExpect = s + 1;
        }
        while (iExpect < kBurst && IsOversized(iExpect)) ++iExpect;
        if ((int)vSeq.size() < nWant) nMissing = nWant - (int)vSeq.size();

        const bool bClosed = g_bClosed.load();
        std::printf("[sendgather] %s: delivered=%zu (want %d) out-of-order=%d bad-body=%ld "
                    "oversized-delivered=%d reports=%ld (want %d) closed=%d\n",
                    tag, vSeq.size(), nWant, nOutOfOrder, g_nBadBody.load(), nOversizedSeen,
                    g_nReports.load(), nOverCount, (int)bClosed);
        if (iFirstBad >= 0)
            std::printf("[sendgather] %s: first out-of-order at delivery %d: seq %d\n",
                        tag, iFirstBad, vSeq[(size_t)iFirstBad]);
        if (bClosed)
            std::printf("[sendgather] %s: FAIL - the LINK was dropped\n", tag);
        else if (g_nBadBody.load() != 0)
            std::printf("[sendgather] %s: FAIL - a frame carried bytes that are not its own\n", tag);
        else if (nOversizedSeen != 0)
            std::printf("[sendgather] %s: FAIL - an oversized message was delivered\n", tag);
        else if (nOutOfOrder != 0 || (int)vSeq.size() != nWant)
            std::printf("[sendgather] %s: FAIL - the burst did not arrive whole and in order "
                        "(missing %d)\n", tag, nMissing);
        else if (g_nReports.load() != nOverCount)
            std::printf("[sendgather] %s: FAIL - %ld reports for %d refused messages\n",
                        tag, g_nReports.load(), nOverCount);
        else
        {
            std::printf("[sendgather] %s: PASS - whole, in order, refusals reported, link kept\n", tag);
            nExit = 0;
        }
        if (nExit != 0) nExit = 1;
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
    short nPortPlain  = (argc >= 2) ? (short)std::atoi(argv[1]) : 7839;
    short nPortCypher = (argc >= 3) ? (short)std::atoi(argv[2]) : 7841;

    std::printf("=== p2p_sendgather - a gathered burst arrives whole and in order (T3) ===\n");
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

    auto rank = [](int v) { return v == 1 ? 3 : v == 3 ? 2 : v == 2 ? 1 : 0; };
    int nExit = rank(nPlain) >= rank(nCypher) ? nPlain : nCypher;
    std::printf("\nRESULT: plain=%d cypher=%d -> exit %d\n", nPlain, nCypher, nExit);
    std::fflush(stdout);
    return nExit;
}
