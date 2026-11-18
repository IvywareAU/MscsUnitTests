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
// perf_ab.cpp — portable (Linux/Windows) throughput+latency A/B for the Targetcore
// message pump.  Same single-process two-hub loopback-TCP setup as wsa_mesh.cpp, but
// instead of one BCast it drives:
//
//   Phase L (latency)   : post 1 BCast, spin until the server delivers it, x K.
//                         Reports serial one-way delivery latency (min/avg/p50/p99/max).
//   Phase T (throughput): post N BCast back-to-back (pipelined), time until the server
//                         has delivered all N.  Reports messages/sec + bytes/sec.
//
// This is LinuxPortPlan.md §8 "Perf sanity": no absolute target beyond "same order of
// magnitude" between Windows-IOCP and Linux-io_uring — it guards against the io_uring
// path accidentally doing SYNCHRONOUS I/O (which would collapse throughput).
//
// The server counts deliveries in an atomic; the main thread posts + times (PostP2PeerMsg
// is the framework's cross-thread send API, safe off the pump thread by design).
//
// Verdict = process EXIT CODE: 0 SUCCESS | 3 TIMEOUT | 1 SETUP.
//
// Tunables via argv or env:  perf_ab [K_latency] [N_throughput] [payloadBytes]
//   defaults: K=2000  N=50000  payload=64
//
// P0 extensions (p2p_performance.md §3.1 B1, 2026-11-18), all by environment so
// every existing command line still means what it meant:
//   PERF_POSTURE=A..E|L  the security posture, the SAME five rows p2p_linkcost
//                        uses: A everything off (the default), B RequireAuth,
//                        C + relay
//                        attestation, D + seal (the tree's defaults), E = D +
//                        SetLinkPolicy(InProcess|Local, Open). L is what this
//                        file measured BEFORE 2026-11-18 - RequireAuth(false)
//                        only - which is NOT A: see the note at kPost. Keys are
//                        generated per run into temp files and deleted at exit.
//                        TWO HUBS CANNOT MEASURE THE SEAL: it is end-to-end and
//                        SealAppMsgOutbound waives it when the link's far end is
//                        the destination, so here D does C's work (measured
//                        2026-11-18: same latency, same frame). The seal's cost
//                        is p2p_linkcost's (three hubs) or B5's relay chain.
//   PERF_TRANSPORT=wsa|dmx|pipe
//                        loopback TCP (default, port 7802), in-process Dmx, or a
//                        named pipe. Trust differs by transport, so E only
//                        relaxes a link whose class the transport can vouch for
//                        - the link state line printed at login says which.
//   frame bytes/msg      read at the RECEIVER off the delivered message: the
//                        adopted image's declared size (a full-mask
//                        PrepareP2Piomage, no copy) - the frame the wire carried,
//                        less the link cypher's own nonce + tag when one is
//                        active. The note adds P3PmsgBSTR::Sizeof, which is the
//                        heap's USED bytes, not the frame.
//                        No library counter exists and P0 changes no library
//                        code, so this is the honest place to read it.
//
// Build (Linux):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore -I../Targetcore \
//       -I../Msgcore/Platform -I../Msgcore/Platform/win-compat perf_ab.cpp \
//       -L../build/Targetcore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/Targetcore -Wl,-rpath,../build/Msgcore -o perf_ab

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerConDmx.h"
#include "P2PeerConPipe.h"
#include "P2PeerMsg.h"
#include "P2PIdentityStore.h"
#include "Msgexception.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <thread>
#include <mutex>
#include <condition_variable>

// P0 suite (p2p_performance.md §3): the shared Stats / PERFJSON / CPU-time
// helpers. Only the reporting is shared; this file keeps its own clock and
// output lines so numbers taken before 2026-11-18 stay comparable.
#include "perf_common.h"

using clk = std::chrono::steady_clock;
static double ns_since(clk::time_point t0)
{ return (double)std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now() - t0).count(); }

// --- narrow-print helper (portable; %s is narrow on glibc) -----------------
static std::string N(const wchar_t* w)
{
    std::string s;
    if (w) for (; *w; ++w) { unsigned long c = (unsigned long)*w; s.push_back(c < 0x80 ? (char)c : '?'); }
    return s;
}

// -------------------------------------------------------------------------
static const short      kTestPort   = 7802;
static const P2PaddrSTR kServerAddr = L"PerfAB.Server";
static const P2PaddrSTR kClientAddr = L"PerfAB.Client";

static std::atomic<long> g_recvCount{0};   // BCasts the server has delivered
static std::atomic<bool> g_loginReady{false};

// --- wait strategy --------------------------------------------------------
// The default waiter busy-spins with yield(); on a core-constrained VM that
// steals a core from the pump threads and inflates the measured per-hop
// latency (a measurement artifact, not the transport floor).  PERF_BLOCKWAIT=1
// makes the main thread BLOCK on a condvar the server notifies — the latency a
// real single-waiter application actually sees.  Run both and compare: the gap
// is the yield-spin's scheduling tax.
static bool                    g_blockWait = false;
static std::mutex              g_wakeMx;
static std::condition_variable g_wakeCv;

// --- posture (PERF_POSTURE) — the rows of p2p_linkcost.cpp, verbatim ------
// L is what this file did before 2026-11-18 - RequireAuth(false) and NOTHING
// else, so RequireRelayAuth / RequireSeal / RequireRevocation stay at their
// library defaults, which are all TRUE (P2PAuthLogin.cpp AuthPolicy ctor). With
// no keys none of them can sign or seal, but they are not free: L vs A is the
// cost of the switches a caller did not know to turn off. Kept so the numbers
// taken before that date (F-P0-7's 109 allocs, E-K's n_sys) stay reproducible.
struct Posture { char cTag; const char* pszName; bool bAuth, bAttest, bSeal, bOpen, bLegacy = false; };
static const Posture kPost[] =
{ { 'L', "legacy: RequireAuth(false) only, the rest at defaults", false, false, false, false, true }
, { 'A', "everything off",                    false, false, false, false }
, { 'B', "RequireAuth only",                  true,  false, false, false }
, { 'C', "+ relay attestation",               true,  true,  false, false }
, { 'D', "+ seal (the tree's defaults)",      true,  true,  true,  false }
, { 'E', "D + SetLinkPolicy(InProcess|Local, Open)", true, true, true, true }
};
static const Posture* g_pPost = &kPost[1];          // A

// --- transport (PERF_TRANSPORT) -------------------------------------------
enum Transport { TrWsa, TrDmx, TrPipe };
static Transport   g_eTr = TrWsa;
static const char* TrName() { return g_eTr == TrDmx ? "dmx" : g_eTr == TrPipe ? "pipe" : "wsa"; }
static LPCTSTR     kDmxSvc  = _T("PerfAB.Dmx");
static LPCTSTR     kPipeName = _T("\\\\.\\pipe\\PerfAB");

// --- what the client's link actually did, read at its login ack -----------
// Without this a posture row is unfalsifiable: "B costs nothing over A" and
// "B never took" print the same numbers (p2p_linkcost's argument).
static std::atomic<int> g_nKeyX{-1}, g_nCypher{-1}, g_nAuthed{-1}, g_nTrust{-1};

// --- frame bytes, read at the receiver ------------------------------------
static std::atomic<long long> g_frameBytes{0};   // sum over delivered messages: wire image
static std::atomic<long long> g_usedBytes{0};    //                              used heap
static std::atomic<long>      g_frameN{0};
static std::atomic<long>      g_badBody{0};      // a delivered body of the wrong length
static size_t                 g_cbBody = 0;

// --- key material (postures B..E), temp files deleted at exit ------------
static std::vector<std::string> g_vTemp;
static std::string g_sCliKey, g_sCliAgr, g_sCliAcl, g_sSrvKey, g_sSrvAgr, g_sSrvAcl;

static std::string TempPath(const char* leaf)
{
    char dir[MAX_PATH + 2] = {0};
    DWORD n = GetTempPathA(MAX_PATH + 1, dir);
    std::string s = (n > 0 && n <= MAX_PATH) ? std::string(dir) : std::string(".\\");
    char pid[32]; std::snprintf(pid, sizeof pid, "%lu", (unsigned long)GetCurrentProcessId());
    s += "perf_ab_"; s += leaf; s += "_"; s += pid; s += ".tmp";
    DeleteFileA(s.c_str());
    g_vTemp.push_back(s);
    return s;
}
static void ScrubTemp() { for (auto& s : g_vTemp) DeleteFileA(s.c_str()); g_vTemp.clear(); }

static bool Provision()
{
    g_sCliKey = TempPath("clikey"); g_sCliAgr = TempPath("cliagr"); g_sCliAcl = TempPath("cliacl");
    g_sSrvKey = TempPath("srvkey"); g_sSrvAgr = TempPath("srvagr"); g_sSrvAcl = TempPath("srvacl");
    unsigned char idC[p2pcng::kEcdsaPubLen], agC[p2pcng::kEcdhPubLen];
    unsigned char idS[p2pcng::kEcdsaPubLen], agS[p2pcng::kEcdhPubLen];
    auto ident = [](const std::string& p, unsigned char* pub) {
        p2pcng::EcdsaP256 k;
        return k.Generate() && p2pcng::SaveIdentity(p.c_str(), k) == p2pcng::IdOk && k.ExportPublic(pub); };
    auto agree = [](const std::string& p, unsigned char* pub) {
        p2pcng::EcdhP256 k;
        return k.Generate() && p2pcng::SaveAgreement(p.c_str(), k) == p2pcng::IdOk && k.ExportPublic(pub); };
    if (!ident(g_sCliKey, idC) || !agree(g_sCliAgr, agC) ||
        !ident(g_sSrvKey, idS) || !agree(g_sSrvAgr, agS)) return false;
    return p2pcng::AppendAllowList(g_sCliAcl.c_str(), "PerfAB.Server", idS, agS) == p2pcng::IdOk
        && p2pcng::AppendAllowList(g_sSrvAcl.c_str(), "PerfAB.Client", idC, agC) == p2pcng::IdOk;
}

// Apply the posture to one hub. bSender: the client seals; the server opens.
static bool ApplyPosture(P2PeerHub& hub, bool bSender)
{
    const Posture& p = *g_pPost;
    if (p.bLegacy) { hub.RequireAuth(false); return true; }
    hub.RequireAuth(p.bAuth);
    hub.RequireRelayAuth(p.bAttest);
    hub.RequireSeal(bSender && p.bSeal);
    hub.RequireRevocation(false);     // per-connection, not per-message (p2p_linkcost)
    // PERF_KEEP=relay,seal,revoke: leave the named switch at its library
    // default (true) - the per-switch split of L minus A.
    if (const char* k = std::getenv("PERF_KEEP"))
    {
        std::string keep = k;
        if (keep.find("relay")  != std::string::npos) hub.RequireRelayAuth(true);
        if (keep.find("seal")   != std::string::npos) hub.RequireSeal(true);
        if (keep.find("revoke") != std::string::npos) hub.RequireRevocation(true);
    }
    if (p.bAuth || p.bAttest || p.bSeal)
    {
        const std::string& key = bSender ? g_sCliKey : g_sSrvKey;
        const std::string& acl = bSender ? g_sCliAcl : g_sSrvAcl;
        if (hub.SetIdentity(key.c_str()) != p2pcng::IdOk ||
            hub.SetAllowList(acl.c_str()) != p2pcng::IdOk) return false;
    }
    if (p.bSeal)
    {
        const std::string& agr = bSender ? g_sCliAgr : g_sSrvAgr;
        if (hub.SetAgreementKey(agr.c_str()) != p2pcng::IdOk) return false;
        if (bSender ? !hub.CanSeal() : !hub.CanOpen()) return false;
    }
    if (p.bOpen)
    {
        hub.SetLinkPolicy(P2PeerConTrust_InProcess, P2PeerLinkPolicy_Open);
        hub.SetLinkPolicy(P2PeerConTrust_Local,     P2PeerLinkPolicy_Open);
    }
    return true;
}

static void NoteDelivered()
{
    g_recvCount.fetch_add(1, std::memory_order_relaxed);
    // Notify under the mutex: without it, this notify can slip into the waiter's
    // check→wait_for gap and be lost, stalling a single-message wait for its whole
    // budget.  Taking the lock serialises against that window (blockWait-only path).
    if (g_blockWait) { std::lock_guard<std::mutex> lk(g_wakeMx); g_wakeCv.notify_one(); }
}

// =========================================================================
class PerfHub : public P2PeerHub
{
public:
    PerfHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr), m_bServer(bServer) {}
    virtual ~PerfHub() {}

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        if (m_bServer)
        {
            if (pMsg)
            {
                // Two relaxed adds; the length check (not a memcmp) keeps the
                // receiver's measured work what it was before 2026-11-18.
                // The WIRE frame is the adopted image's declared size, which a
                // full-mask prepare returns without a copy (msgcore_bench:
                // serialize = 35 ns). Sizeof() is the USED part of the heap; the
                // gap between the two is what M1 trims.
                pMsg->PrepareP2Piomage(~(DWORD)0);
                g_frameBytes.fetch_add((long long)pMsg->P2PiomageSize(), std::memory_order_relaxed);
                pMsg->ReleaseP2Piomage();
                g_usedBytes.fetch_add((long long)pMsg->Sizeof(), std::memory_order_relaxed);
                g_frameN.fetch_add(1, std::memory_order_relaxed);
                if ((size_t)pMsg->DataSize() != g_cbBody) g_badBody.fetch_add(1);
            }
            NoteDelivered();
        }
        return msgHANDLED;
    }

    // A hub holding an identity signs its login even where the peer requires no
    // authentication, and the stock handler refuses a login carrying data. The
    // GUARD keeps this from bypassing the auth gate the posture is measuring:
    // only where nothing is required is the login accepted directly
    // (p2p_linkcost / p2p_sealhop, same reason).
    virtual conRESULT On_ConLogin(P2PeerCon* pCon, P2PaddrSTR that,
                                  const void* pv, P2Psize_t n) override
    {
        if (IsAuthRequired() || (!pv && !n))
            return P2PeerHub::On_ConLogin(pCon, that, pv, n);
        pCon->OnLogin(that);
        pCon->LoginAck(that, 0, 0);
        return conHANDLED;
    }

    virtual conRESULT On_ConLoginAck(P2PeerCon* pCon, P2PaddrSTR a, P2PaddrSTR b,
                                     const void* p, P2Psize_t n) override
    {
        conRESULT r = P2PeerHub::On_ConLoginAck(pCon, a, b, p, n);
        if (!m_bServer)
        {
            if (pCon)
            {
                g_nKeyX   = pCon->IsKeyXDone()      ? 1 : 0;
                g_nCypher = pCon->IsCypherActive()  ? 1 : 0;
                g_nAuthed = pCon->IsAuthenticated() ? 1 : 0;
                g_nTrust  = (int)pCon->EffectiveTrust();
            }
            g_loginReady.store(true, std::memory_order_release);
        }
        return r;
    }
    virtual conRESULT On_ConClose(P2PeerCon* pCon) override
    { return P2PeerHub::On_ConClose(pCon); }

private:
    bool m_bServer;
};

// =========================================================================
static void PostOne(PerfHub& cli, const std::vector<wchar_t>& body)
{
    P2Psize_t nBytes = (P2Psize_t)(body.size() * sizeof(wchar_t));
    P2PeerMsg32* pMsg = new P2PeerMsg32(kClientAddr, kServerAddr, P2Pmsg_BCast,
                                        body.data(), nBytes);
    cli.PostP2PeerMsg(pMsg);
}

// W6 (p2p_PumpPerf.md) batch-sender micro-bench: when g_batch>0, post `count`
// BCasts in chunks of g_batch via the batch producer API (one lookup + one lock
// + one wake per chunk); otherwise fall back to the single-post path.  The chunk
// is bounded (<< the queue cap, s_cP2PmsgMAX) so the pump can drain between
// chunks.  That cap read "10000" here until 2026-08-18 and was 50000 - the
// figure came from the diagnostic, which was wrong (ProductionPlan Stage 0 step
// 2, asserted by p2p_pumpbound).  Naming the constant rather than a number is
// the point: this comment is a bound-relative claim, so it must not carry a copy
// of the bound.
static size_t g_batch = 0;
static void PostMany(PerfHub& cli, const std::vector<wchar_t>& body, long count)
{
    if (g_batch == 0) { for (long i = 0; i < count; ++i) PostOne(cli, body); return; }
    P2Psize_t nBytes = (P2Psize_t)(body.size() * sizeof(wchar_t));
    std::vector<P2PeerMsg*> chunk; chunk.reserve(g_batch);
    long i = 0;
    while (i < count)
    {
        size_t n = (size_t)std::min<long>((long)g_batch, count - i);
        chunk.clear();
        for (size_t k = 0; k < n; ++k)
            chunk.push_back(new P2PeerMsg32(kClientAddr, kServerAddr, P2Pmsg_BCast,
                                            body.data(), nBytes));
        cli.PostP2PeerMsgBatch(chunk.data(), chunk.size());
        i += (long)n;
    }
}

// wait until g_recvCount >= target or the deadline elapses; returns true on reached.
// Two strategies (see g_blockWait): yield-spin (default) or condvar block.
static bool WaitCount(long target, double budget_ms)
{
    clk::time_point t0 = clk::now();
    if (g_blockWait)
    {
        std::unique_lock<std::mutex> lk(g_wakeMx);
        while (g_recvCount.load(std::memory_order_relaxed) < target)
        {
            double left = budget_ms - ns_since(t0) / 1e6;
            if (left <= 0) return false;
            g_wakeCv.wait_for(lk, std::chrono::microseconds((long long)(left * 1000)));
        }
        return true;
    }
    while (g_recvCount.load(std::memory_order_relaxed) < target)
    {
        if (ns_since(t0) / 1e6 > budget_ms) return false;
        std::this_thread::yield();
    }
    return true;
}

int main(int argc, char* argv[])
{
    long  K       = argc > 1 ? std::atol(argv[1]) : 2000;    // latency iters
    long  Nthru   = argc > 2 ? std::atol(argv[2]) : 50000;   // throughput msgs
    int   payload = argc > 3 ? std::atoi(argv[3]) : 64;      // payload bytes
    if (payload < (int)sizeof(wchar_t)) payload = sizeof(wchar_t);

    { const char* bw = std::getenv("PERF_BLOCKWAIT");
      g_blockWait = bw && bw[0] && bw[0] != '0'; }
    { const char* bs = std::getenv("PERF_BATCH");            // W6 batch-sender size
      g_batch = bs ? (size_t)std::max<long>(0, std::atol(bs)) : 0; }
    { const char* ps = std::getenv("PERF_POSTURE");
      if (ps && *ps)
      {
          g_pPost = nullptr;
          for (const Posture& p : kPost) if (p.cTag == (char)std::toupper((unsigned char)*ps)) g_pPost = &p;
          if (!g_pPost) { std::printf("FATAL: PERF_POSTURE=%s (want A..E or L).\n", ps); return 1; }
      } }
    { const char* ts = std::getenv("PERF_TRANSPORT");
      std::string t = ts ? ts : "";
      if (t.empty() || t == "wsa") g_eTr = TrWsa;
      else if (t == "dmx")         g_eTr = TrDmx;
      else if (t == "pipe")        g_eTr = TrPipe;
      else { std::printf("FATAL: PERF_TRANSPORT=%s (want wsa|dmx|pipe).\n", t.c_str()); return 1; } }

    perf::PrintBox("perf_ab");
    std::printf("=== perf_ab — Targetcore loopback-TCP perf A/B ===\n");
#if defined(_WIN32)
    std::printf("backend: Windows / IOCP\n");
#else
    std::printf("backend: Linux / io_uring\n");
#endif
    std::printf("K(latency)=%ld  N(throughput)=%ld  payload=%dB  port=%d\n",
                K, Nthru, payload, (int)kTestPort);
    std::printf("wait=%s  (set PERF_BLOCKWAIT=1 to measure the blocking-waiter floor)\n",
                g_blockWait ? "condvar-block" : "yield-spin");
    std::printf("batch=%zu  (set PERF_BATCH=N for the W6 batch-sender path in Phase T)\n",
                g_batch);
    std::printf("posture=%c (%s)  transport=%s  (PERF_POSTURE=A..E|L, PERF_TRANSPORT=wsa|dmx|pipe)\n",
                g_pPost->cTag, g_pPost->pszName, TrName());
    if (const char* k = std::getenv("PERF_KEEP"))
        std::printf("PERF_KEEP=%s: those switches stay at their default (true)\n", k);
    if (g_pPost->bSeal)
        // P2PeerCon::SealAppMsgOutbound returns early when the link's far end IS
        // the destination: the seal is end-to-end and is waived on the last hop,
        // and with two hubs every hop is the last. So D costs what C costs here,
        // by design. The seal's cost needs a relay - p2p_linkcost's three hubs,
        // or B5's relay chain.
        std::printf("NOTE: two hubs, one hop: the seal is waived on the last hop "
                    "(P2PeerCon.cpp SealAppMsgOutbound), so %c measures C's work here.\n",
                    g_pPost->cTag);
    std::printf("\n");
    std::fflush(stdout);

    // fixed payload buffer (NUL-terminated-ish; content irrelevant to timing)
    std::vector<wchar_t> body((size_t)payload / sizeof(wchar_t), L'x');
    if (!body.empty()) body.back() = L'\0';
    g_cbBody = body.size() * sizeof(wchar_t);

    if (!StartupP2Pmsg(64)) { std::printf("FATAL: StartupP2Pmsg failed.\n"); return 1; }
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);

    const Posture& post = *g_pPost;
    if ((post.bAuth || post.bAttest || post.bSeal) && !Provision())
    { std::printf("FATAL: key provisioning failed.\n"); ScrubTemp(); return 1; }

    PerfHub oServer(kServerAddr, true);
    if (!ApplyPosture(oServer, false))
    { std::printf("FATAL: server posture %c did not take.\n", post.cTag); ScrubTemp(); return 1; }
    HANDLE hS = oServer.SpawnHub();
    if (!hS) { std::printf("FATAL: server SpawnHub failed.\n"); return 1; }
    P2PeerCon* pSvc =
        g_eTr == TrDmx  ? (P2PeerCon*)P2PeerConDmx::ServiceFactory(kClientAddr, kDmxSvc)
      : g_eTr == TrPipe ? (P2PeerCon*)P2PeerConPipe::ServiceFactory(kClientAddr, kPipeName)
      :                   (P2PeerCon*)P2PeerConWsa::ServiceFactory(kClientAddr, kTestPort);
    if (!pSvc) { std::printf("FATAL: ServiceFactory failed.\n"); return 1; }
    oServer.PostP2PeerCon(pSvc);
    Sleep(750);

    PerfHub oClient(kClientAddr, false);
    if (!ApplyPosture(oClient, true))
    { std::printf("FATAL: client posture %c did not take.\n", post.cTag); ScrubTemp(); return 1; }
    HANDLE hC = oClient.SpawnHub();
    if (!hC) { std::printf("FATAL: client SpawnHub failed.\n"); return 1; }
    P2PeerCon* pCli =
        g_eTr == TrDmx  ? (P2PeerCon*)P2PeerConDmx::ClientFactory(kServerAddr, kDmxSvc)
      : g_eTr == TrPipe ? (P2PeerCon*)P2PeerConPipe::ClientFactory(kServerAddr, kPipeName)
      :                   (P2PeerCon*)P2PeerConWsa::ClientFactory(kServerAddr, L"127.0.0.1", kTestPort);
    if (!pCli) { std::printf("FATAL: ClientFactory failed.\n"); return 1; }
    oClient.PostP2PeerCon(pCli);

    // wait for login handshake
    { clk::time_point t0 = clk::now();
      while (!g_loginReady.load(std::memory_order_acquire))
      { if (ns_since(t0)/1e6 > 10000) { std::printf("TIMEOUT: no login ack.\n"); ScrubTemp(); return 3; }
        std::this_thread::sleep_for(std::chrono::milliseconds(1)); } }
    std::printf("login ack received — link ready.  link: keyx=%d cypher=%d authed=%d trust=%d\n\n",
                g_nKeyX.load(), g_nCypher.load(), g_nAuthed.load(), g_nTrust.load());
    std::fflush(stdout);

    // A posture that asked for authentication and got an unauthenticated link
    // would post posture A's numbers under B's name. Refuse to measure it.
    if (post.bAuth && g_nAuthed.load() != 1 && !post.bOpen)
    { std::printf("FATAL: posture %c asked for an authenticated link and did not get one.\n",
                  post.cTag); ScrubTemp(); return 1; }

    // One tag for every row this run reports: payload/waiter-or-batch/posture/transport.
    std::string tag = std::string("/") + post.cTag + "/" + TrName();
    if (const char* k = std::getenv("PERF_KEEP")) if (*k) tag += std::string("/keep=") + k;

    int nExit = 0;

    // ---- warmup (exclude connection-warm effects) ------------------------
    {
        long base = g_recvCount.load();
        for (int i = 0; i < 200; ++i) PostOne(oClient, body);
        if (!WaitCount(base + 200, 5000)) { std::printf("TIMEOUT: warmup.\n"); nExit = 3; }
    }

    // ---- Phase L: serial one-way latency ---------------------------------
    if (!nExit)
    {
        std::vector<double> us; us.reserve(K);
        double cpu0 = perf::CpuNow();
        unsigned long long a0 = perf::Allocs();   // counted on Linux only (perf_common.h)
        for (long i = 0; i < K; ++i)
        {
            long target = g_recvCount.load() + 1;
            clk::time_point t0 = clk::now();
            PostOne(oClient, body);
            if (!WaitCount(target, 5000)) { std::printf("TIMEOUT: latency iter %ld.\n", i); nExit = 3; break; }
            us.push_back(ns_since(t0) / 1e3);
        }
        if (!nExit)
        {
            std::sort(us.begin(), us.end());
            double sum = 0; for (double v : us) sum += v;
            auto pct = [&](double p){ return us[(size_t)std::min<double>(us.size()-1, p*us.size())]; };
            std::printf("LATENCY (serial one-way, %zu samples, %dB):\n", us.size(), payload);
            std::printf("  min=%.1f  p50=%.1f  avg=%.1f  p99=%.1f  max=%.1f  (microseconds)\n\n",
                        us.front(), pct(0.50), sum/us.size(), pct(0.99), us.back());
            // CPU us per message: whole process (both hubs, both pumps, the
            // waiter), so a yield-spin waiter shows up here and not in wall time.
            double cpuPerMsg = (perf::CpuNow() - cpu0) * 1e6 / us.size();
            double allocsPerMsg = perf::AllocsCounted()
                ? (double)(perf::Allocs() - a0) / us.size() : -1;
            std::string param = std::to_string(payload) + "B/" +
                                (g_blockWait ? "condvar" : "yield") + tag;
            perf::Report("perf_ab", "latency_oneway", param, "us",
                         perf::Summarise(us), cpuPerMsg, allocsPerMsg);
            std::printf("\n");
            std::fflush(stdout);
        }
    }

    // ---- Phase T: pipelined throughput -----------------------------------
    if (!nExit)
    {
        long base = g_recvCount.load();
        double cpu0 = perf::CpuNow();
        unsigned long long a0 = perf::Allocs();
        clk::time_point t0 = clk::now();
        PostMany(oClient, body, Nthru);   // W6: batch when PERF_BATCH>0, else single-post
        double post_ms = ns_since(t0) / 1e6;
        bool ok = WaitCount(base + Nthru, 60000);
        double drain_ms = ns_since(t0) / 1e6;
        if (!ok) { std::printf("TIMEOUT: throughput drain (got %ld/%ld).\n",
                               g_recvCount.load() - base, Nthru); nExit = 3; }
        else
        {
            double msgs_s  = Nthru / (drain_ms / 1e3);
            double mib_s   = (double)Nthru * payload / (drain_ms/1e3) / (1024.0*1024.0);
            std::printf("THROUGHPUT (pipelined, %ld msgs x %dB):\n", Nthru, payload);
            std::printf("  post-all=%.1f ms  drain-all=%.1f ms\n", post_ms, drain_ms);
            std::printf("  %.0f msgs/sec   %.1f MiB/sec   %.2f us/msg\n\n",
                        msgs_s, mib_s, (drain_ms*1e3)/Nthru);
            // One sample, so min = p50 = max: the driver's interleaved runs
            // supply the distribution. Unit msgs/s; cpu_per_op is CPU us/msg.
            perf::Stats s; s.n = 1; s.min = s.p50 = s.avg = s.p99 = s.max = msgs_s;
            std::string param = std::to_string(payload) + "B/batch" + std::to_string(g_batch) + tag;
            perf::Report("perf_ab", "throughput", param, "msgs/s", s,
                         (perf::CpuNow() - cpu0) * 1e6 / Nthru,
                         perf::AllocsCounted() ? (double)(perf::Allocs() - a0) / Nthru : -1,
                         nullptr, "us/msg");
            std::fflush(stdout);
        }
    }

    // ---- frame bytes per delivered message, and the body check -----------
    if (!nExit)
    {
        long nF = g_frameN.load();
        if (nF > 0)
        {
            double avg = (double)g_frameBytes.load() / nF;
            perf::Stats s; s.n = (size_t)nF; s.min = s.p50 = s.avg = s.p99 = s.max = avg;
            double used = (double)g_usedBytes.load() / nF;
            char note[160];
            std::snprintf(note, sizeof note, "payload=%zu B, heap used=%.0f B, frame/payload=%.1fx%s",
                          g_cbBody, used, g_cbBody ? avg / g_cbBody : 0.0,
                          g_nCypher.load() == 1 ? ", + link cypher overhead" : "");
            perf::Report("perf_ab", "frame_bytes", std::to_string(payload) + "B" + tag,
                         "B/msg", s, -1, -1, note);
        }
        if (g_badBody.load() != 0)
        {
            std::printf("FAIL: %ld delivered bodies had the wrong length.\n", g_badBody.load());
            nExit = 1;
        }
    }

    // ---- shutdown --------------------------------------------------------
    oClient.CloseHub();
    oServer.CloseHub();
    WaitForSingleObject(hC, 3000);
    WaitForSingleObject(hS, 3000);
    CloseHandle(hC); CloseHandle(hS);
    CleanupP2Pmsg();
    WSACleanup();
    ScrubTemp();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
