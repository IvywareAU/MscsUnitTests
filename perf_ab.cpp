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
// perf_ab.cpp — portable (Linux/Windows) throughput+latency A/B for the TargetCore
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
// Build (Linux):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore -I../TargetCore \
//       -I../Msgcore/Platform -I../Msgcore/Platform/win-compat perf_ab.cpp \
//       -L../build/TargetCore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/TargetCore -Wl,-rpath,../build/Msgcore -o perf_ab

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

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
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* /*pMsg*/) override
    { if (m_bServer) NoteDelivered(); return msgHANDLED; }

    virtual conRESULT On_ConLoginAck(P2PeerCon* pCon, P2PaddrSTR a, P2PaddrSTR b,
                                     const void* p, P2Psize_t n) override
    {
        conRESULT r = P2PeerHub::On_ConLoginAck(pCon, a, b, p, n);
        if (!m_bServer) g_loginReady.store(true, std::memory_order_release);
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

    std::printf("=== perf_ab — TargetCore loopback-TCP perf A/B ===\n");
#if defined(_WIN32)
    std::printf("backend: Windows / IOCP\n");
#else
    std::printf("backend: Linux / io_uring\n");
#endif
    std::printf("K(latency)=%ld  N(throughput)=%ld  payload=%dB  port=%d\n",
                K, Nthru, payload, (int)kTestPort);
    std::printf("wait=%s  (set PERF_BLOCKWAIT=1 to measure the blocking-waiter floor)\n",
                g_blockWait ? "condvar-block" : "yield-spin");
    std::printf("batch=%zu  (set PERF_BATCH=N for the W6 batch-sender path in Phase T)\n\n",
                g_batch);
    std::fflush(stdout);

    // fixed payload buffer (NUL-terminated-ish; content irrelevant to timing)
    std::vector<wchar_t> body((size_t)payload / sizeof(wchar_t), L'x');
    if (!body.empty()) body.back() = L'\0';

    if (!StartupP2Pmsg(64)) { std::printf("FATAL: StartupP2Pmsg failed.\n"); return 1; }
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);

    PerfHub oServer(kServerAddr, true);
    oServer.RequireAuth ( false );
    HANDLE hS = oServer.SpawnHub();
    if (!hS) { std::printf("FATAL: server SpawnHub failed.\n"); return 1; }
    P2PeerConWsa* pSvc = P2PeerConWsa::ServiceFactory(kClientAddr, kTestPort);
    if (!pSvc) { std::printf("FATAL: ServiceFactory failed.\n"); return 1; }
    oServer.PostP2PeerCon(pSvc);
    Sleep(750);

    PerfHub oClient(kClientAddr, false);
    oClient.RequireAuth ( false );
    HANDLE hC = oClient.SpawnHub();
    if (!hC) { std::printf("FATAL: client SpawnHub failed.\n"); return 1; }
    P2PeerConWsa* pCli = P2PeerConWsa::ClientFactory(kServerAddr, L"127.0.0.1", kTestPort);
    if (!pCli) { std::printf("FATAL: ClientFactory failed.\n"); return 1; }
    oClient.PostP2PeerCon(pCli);

    // wait for login handshake
    { clk::time_point t0 = clk::now();
      while (!g_loginReady.load(std::memory_order_acquire))
      { if (ns_since(t0)/1e6 > 10000) { std::printf("TIMEOUT: no login ack.\n"); return 3; }
        std::this_thread::sleep_for(std::chrono::milliseconds(1)); } }
    std::printf("login ack received — link ready.\n\n");
    std::fflush(stdout);

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
            std::fflush(stdout);
        }
    }

    // ---- Phase T: pipelined throughput -----------------------------------
    if (!nExit)
    {
        long base = g_recvCount.load();
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
            std::fflush(stdout);
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

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
