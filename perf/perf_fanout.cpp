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
// perf_fanout.cpp -- B5 of p2p_performance.md §3.1: what a message costs as the
// hub it passes through holds more connections, and as the path gets longer.
//
//   perf_fanout fan   C [K] [N]   one hub "Fan", one sending child "Fan.S" and C
//                                 receiving children "Fan.R000".. on ONE loopback
//                                 TCP listener (the P2PeerWeb shape: many
//                                 sessions, one hub). Every message is S -> Fan
//                                 -> R, so Fan's RouteP2PeerMsg picks one of C+1
//                                 connections. Phases:
//                                   lat_first  serial, to R000 (connected 2nd)
//                                   lat_last   serial, to R[C-1] (connected last)
//                                   thr_last   N pipelined to R[C-1]
//                                   all        one message to EVERY receiver,
//                                              timed until all C are delivered
//                                 Connections are kept in creation order
//                                 (P2Pwin32.cpp AddTail) and the route walks
//                                 them with EnumP2PmsgCon, which rescans from
//                                 the head and retakes the hub lock per step -
//                                 so lat_last - lat_first IS the T4 cost, and
//                                 its growth with C is the O(n^2) the plan
//                                 predicts. Each receiver is its own hub with
//                                 its own pump: C=250 is 252 hubs, under the
//                                 256 MAX_P2PmsgHub limit (P2Peer.h).
//
//   perf_fanout chain H [K] [N]   H+1 hubs "Ch" <- "Ch.L1" <- "Ch.L1.L2" ...;
//                                 the deepest originates, "Ch" is the
//                                 destination, H-1 hubs relay. Phases lat and
//                                 thr. THIS is where the seal can be measured:
//                                 SealAppMsgOutbound waives it on the last hop,
//                                 so H=1 at posture D does C's work and H>=2
//                                 seals at the origin and opens at "Ch".
//
// One topology per PROCESS, on purpose: the hub limit is per process and
// p2p_linkcost records what reusing addresses a millisecond apart did.
//
// Environment, same meaning as perf_ab (B1):
//   PERF_POSTURE=A..E|L   default A. Every hub shares ONE identity and ONE
//                         agreement key; the allow-list names every address
//                         in the topology with them. Not a trust model, a
//                         measurement fixture: the cost per message is the
//                         same, and the per-address entries are what make the
//                         hubs distinct peers.
//   PERF_KEEP=relay,seal,revoke   leave those switches at their default.
//   PERF_WAIVE=0          WaiveEndToEndInProcess(false) on every hub: the
//                         default before Targetcore 3.6.0. Unset = the library
//                         default (on since 3.6.0). Only a Dmx chain differs.
//   PERF_TRANSPORT=wsa|dmx  chain only (fan is wsa: one listener is the shape
//                         under test; Dmx needs a service per peer, which
//                         would double the list the route walks).
// Ports: fan 7860, chain 7861..7861+H-1.
//
// Exit: 0 ran | 1 setup or a correctness check failed (wrong body length,
// a message delivered to a hub that was not its destination, a posture that
// did not take) | 3 timeout.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerConDmx.h"
#include "P2PeerMsg.h"
#include "P2PIdentityStore.h"
#include "Msgexception.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <thread>

#include "perf_common.h"

#if !defined(_WIN32)
#  include <sys/resource.h>
#endif

using clk = perf::clk;

// Linux: a hub holds ~5 descriptors (its io_uring, wake eventfd, sockets), so
// the default soft RLIMIT_NOFILE of 1024 stops SpawnHub at ~200 hubs
// (measured 2026-11-18: "FATAL: SpawnHub Fan.R202"). Raise the soft limit to
// the hard one, as a 250-session server has to. Not a cost under test.
static void RaiseFdLimit()
{
#if !defined(_WIN32)
    rlimit r;
    if (getrlimit(RLIMIT_NOFILE, &r) == 0 && r.rlim_cur < r.rlim_max)
    {
        rlim_t was = r.rlim_cur;
        r.rlim_cur = r.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &r) == 0)
            std::printf("RLIMIT_NOFILE soft %lu -> %lu\n", (unsigned long)was, (unsigned long)r.rlim_cur);
    }
#endif
}

static std::string N(const std::wstring& w)
{
    std::string s;
    for (wchar_t c : w) s.push_back((unsigned long)c < 0x80 ? (char)c : '?');
    return s;
}

// --- posture: the same rows as perf_ab / p2p_linkcost ----------------------
struct Posture { char cTag; const char* pszName; bool bAuth, bAttest, bSeal, bOpen, bLegacy = false; };
static const Posture kPost[] =
{ { 'L', "legacy: RequireAuth(false) only, the rest at defaults", false, false, false, false, true }
, { 'A', "everything off",                    false, false, false, false }
, { 'B', "RequireAuth only",                  true,  false, false, false }
, { 'C', "+ relay attestation",               true,  true,  false, false }
, { 'D', "+ seal (the tree's defaults)",      true,  true,  true,  false }
, { 'E', "D + SetLinkPolicy(InProcess|Local, Open)", true, true, true, true }
};
static const Posture* g_pPost = &kPost[1];

enum Role { RoleOrigin, RoleRelay, RoleDest };

static bool g_bDmx = false;
static const short kFanPort   = 7860;
static const short kChainPort = 7861;

// --- key material: ONE identity + ONE agreement key, temp files ------------
static std::vector<std::string> g_vTemp;
static std::string g_sKey, g_sAgr, g_sAcl;

static std::string TempPath(const char* leaf)
{
    char dir[MAX_PATH + 2] = {0};
    DWORD n = GetTempPathA(MAX_PATH + 1, dir);
    std::string s = (n > 0 && n <= MAX_PATH) ? std::string(dir) : std::string(".\\");
    char pid[32]; std::snprintf(pid, sizeof pid, "%lu", (unsigned long)GetCurrentProcessId());
    s += "perf_fanout_"; s += leaf; s += "_"; s += pid; s += ".tmp";
    DeleteFileA(s.c_str());
    g_vTemp.push_back(s);
    return s;
}
static void ScrubTemp() { for (auto& s : g_vTemp) DeleteFileA(s.c_str()); g_vTemp.clear(); }

static bool Provision(const std::vector<std::wstring>& vAddr)
{
    g_sKey = TempPath("key"); g_sAgr = TempPath("agr"); g_sAcl = TempPath("acl");
    unsigned char id[p2pcng::kEcdsaPubLen], ag[p2pcng::kEcdhPubLen];
    p2pcng::EcdsaP256 k; p2pcng::EcdhP256 a;
    if (!k.Generate() || p2pcng::SaveIdentity(g_sKey.c_str(), k) != p2pcng::IdOk || !k.ExportPublic(id))
        return false;
    if (!a.Generate() || p2pcng::SaveAgreement(g_sAgr.c_str(), a) != p2pcng::IdOk || !a.ExportPublic(ag))
        return false;
    for (const std::wstring& w : vAddr)
        if (p2pcng::AppendAllowList(g_sAcl.c_str(), N(w).c_str(), id, ag) != p2pcng::IdOk)
            return false;
    return true;
}

static bool ApplyPosture(P2PeerHub& hub, Role eRole)
{
    const Posture& p = *g_pPost;
    if (p.bLegacy) { hub.RequireAuth(false); return true; }
    hub.RequireAuth(p.bAuth);
    hub.RequireRelayAuth(p.bAttest);
    hub.RequireSeal(eRole == RoleOrigin && p.bSeal);
    hub.RequireRevocation(false);
    if (const char* k = std::getenv("PERF_KEEP"))
    {
        std::string keep = k;
        if (keep.find("relay")  != std::string::npos) hub.RequireRelayAuth(true);
        if (keep.find("seal")   != std::string::npos) hub.RequireSeal(true);
        if (keep.find("revoke") != std::string::npos) hub.RequireRevocation(true);
    }
    // PERF_WAIVE=0: the pre-3.6.0 default (waiver off), for the A/B that
    // measured making WaiveEndToEndInProcess the default (decision 2).
    if (const char* w = std::getenv("PERF_WAIVE"); w && std::strcmp(w, "0") == 0)
        hub.WaiveEndToEndInProcess(false);
    if (p.bAuth || p.bAttest || p.bSeal)
        if (hub.SetIdentity(g_sKey.c_str()) != p2pcng::IdOk ||
            hub.SetAllowList(g_sAcl.c_str()) != p2pcng::IdOk) return false;
    // A relay carries what it cannot read and holds no agreement key -
    // p2p_linkcost's middle hub, for P2PAuthLogin.h's reason.
    if (p.bSeal && eRole != RoleRelay)
    {
        if (hub.SetAgreementKey(g_sAgr.c_str()) != p2pcng::IdOk) return false;
        if (eRole == RoleOrigin ? !hub.CanSeal() : !hub.CanOpen()) return false;
    }
    if (p.bOpen)
    {
        hub.SetLinkPolicy(P2PeerConTrust_InProcess, P2PeerLinkPolicy_Open);
        hub.SetLinkPolicy(P2PeerConTrust_Local,     P2PeerLinkPolicy_Open);
    }
    return true;
}

// --- run state ----------------------------------------------------------------
static std::atomic<long>      g_recv{0};        // deliveries at a destination
static std::atomic<long>      g_stray{0};       // deliveries anywhere else
static std::atomic<long>      g_badBody{0};
static std::atomic<long>      g_acks{0};        // client-side login acks
static std::atomic<int>       g_nAuthed{-1}, g_nTrust{-1}, g_nCypher{-1};
static std::atomic<long long> g_frameBytes{0};
static std::atomic<long>      g_frameN{0};
static size_t                 g_cbBody = 0;

class FanHub : public P2PeerHub
{
public:
    FanHub(const std::wstring& a, Role r) : P2PeerHub(a.c_str()), m_eRole(r) {}
    virtual ~FanHub() {}

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        if (m_eRole != RoleDest) { g_stray.fetch_add(1); return msgHANDLED; }
        if (pMsg)
        {
            pMsg->PrepareP2Piomage(~(DWORD)0);
            g_frameBytes.fetch_add((long long)pMsg->P2PiomageSize(), std::memory_order_relaxed);
            pMsg->ReleaseP2Piomage();
            g_frameN.fetch_add(1, std::memory_order_relaxed);
            if ((size_t)pMsg->DataSize() != g_cbBody) g_badBody.fetch_add(1);
        }
        g_recv.fetch_add(1, std::memory_order_release);
        return msgHANDLED;
    }

    // perf_ab's guarded login: accepted directly only where nothing is required.
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
        if (pCon && g_nAuthed.load() < 0)
        {
            g_nAuthed = pCon->IsAuthenticated() ? 1 : 0;
            g_nTrust  = (int)pCon->EffectiveTrust();
            g_nCypher = pCon->IsCypherActive() ? 1 : 0;
        }
        g_acks.fetch_add(1, std::memory_order_release);
        return r;
    }

private:
    Role m_eRole;
};

struct Node
{
    std::wstring            addr;
    std::unique_ptr<FanHub> hub;
    HANDLE                  h = nullptr;
};

static bool WaitAtLeast(std::atomic<long>& c, long target, double ms)
{
    clk::time_point t0 = clk::now();
    while (c.load(std::memory_order_acquire) < target)
    {
        if (perf::NsSince(t0) / 1e6 > ms) return false;
        std::this_thread::yield();
    }
    return true;
}

static void Post(FanHub& from, const std::wstring& src, const std::wstring& dst,
                 const std::vector<unsigned char>& body)
{
    from.PostP2PeerMsg(new P2PeerMsg32(src.c_str(), dst.c_str(), P2Pmsg_BCast,
                                       body.data(), (P2Psize_t)body.size()));
}

static std::string g_tag;      // "/A/wsa" etc.

// serial one-way latency to one destination; returns false on timeout
static bool Latency(const char* kase, const std::string& param, Node& from, const std::wstring& dst,
                    const std::vector<unsigned char>& body, long K)
{
    std::vector<double> us; us.reserve((size_t)K);
    double cpu0 = perf::CpuNow();
    unsigned long long a0 = perf::Allocs();
    for (long i = 0; i < K; ++i)
    {
        long target = g_recv.load() + 1;
        clk::time_point t0 = clk::now();
        Post(*from.hub, from.addr, dst, body);
        if (!WaitAtLeast(g_recv, target, 10000))
        { std::printf("TIMEOUT: %s iter %ld.\n", kase, i); return false; }
        us.push_back(perf::NsSince(t0) / 1e3);
    }
    perf::Report("perf_fanout", kase, param + g_tag, "us", perf::Summarise(us),
                 (perf::CpuNow() - cpu0) * 1e6 / K,
                 perf::AllocsCounted() ? (double)(perf::Allocs() - a0) / K : -1);
    return true;
}

static bool Throughput(const char* kase, const std::string& param, Node& from, const std::wstring& dst,
                       const std::vector<unsigned char>& body, long Nmsg)
{
    long base = g_recv.load();
    double cpu0 = perf::CpuNow();
    unsigned long long a0 = perf::Allocs();
    clk::time_point t0 = clk::now();
    for (long i = 0; i < Nmsg; ++i) Post(*from.hub, from.addr, dst, body);
    if (!WaitAtLeast(g_recv, base + Nmsg, 120000))
    { std::printf("TIMEOUT: %s (got %ld/%ld).\n", kase, g_recv.load() - base, Nmsg); return false; }
    double s = perf::NsSince(t0) / 1e9;
    perf::Stats st; st.n = 1; st.min = st.p50 = st.avg = st.p99 = st.max = Nmsg / s;
    perf::Report("perf_fanout", kase, param + g_tag, "msgs/s", st,
                 (perf::CpuNow() - cpu0) * 1e6 / Nmsg,
                 perf::AllocsCounted() ? (double)(perf::Allocs() - a0) / Nmsg : -1,
                 nullptr, "us/msg");
    return true;
}

static void Shutdown(std::vector<Node>& v)
{
    // Leaves first, root last: a hub closing under a live child is a teardown
    // path this bench does not exist to exercise.
    for (size_t i = v.size(); i-- > 0;) if (v[i].h) v[i].hub->CloseHub();
    for (size_t i = v.size(); i-- > 0;)
        if (v[i].h) { WaitForSingleObject(v[i].h, 5000); CloseHandle(v[i].h); v[i].h = nullptr; }
    v.clear();
}

// Closes every spawned hub on EVERY return path of RunFan/RunChain - an
// early "return 3" with live pumps would destroy hubs under their threads.
struct CloseAll
{
    std::vector<Node>& v;
    ~CloseAll() { Shutdown(v); }
};

static bool Spawn(Node& n)
{
    n.h = n.hub->SpawnHub();
    return n.h != nullptr;
}

// =============================================================================
static int RunFan(long C, long K, long Nmsg, const std::vector<unsigned char>& body)
{
    std::printf("topology: Fan + Fan.S + %ld receivers on one Wsa listener, port %d (%ld hubs)\n\n",
                C, (int)kFanPort, C + 2);
    std::vector<Node> v((size_t)C + 2);
    CloseAll guard{v};
    v[0].addr = L"Fan";  v[1].addr = L"Fan.S";
    for (long i = 0; i < C; ++i)
    { wchar_t b[32]; std::swprintf(b, 32, L"Fan.R%03ld", i); v[(size_t)i + 2].addr = b; }

    std::vector<std::wstring> vAll; for (auto& n : v) vAll.push_back(n.addr);
    const Posture& post = *g_pPost;
    if ((post.bAuth || post.bAttest || post.bSeal) && !Provision(vAll))
    { std::printf("FATAL: key provisioning failed.\n"); return 1; }

    v[0].hub.reset(new FanHub(v[0].addr, RoleRelay));
    v[1].hub.reset(new FanHub(v[1].addr, RoleOrigin));
    for (long i = 0; i < C; ++i) v[(size_t)i + 2].hub.reset(new FanHub(v[(size_t)i + 2].addr, RoleDest));
    for (auto& n : v)
        if (!ApplyPosture(*n.hub, &n == &v[0] ? RoleRelay : &n == &v[1] ? RoleOrigin : RoleDest))
        { std::printf("FATAL: posture %c did not take on %s.\n", post.cTag, N(n.addr).c_str()); return 1; }

    if (!Spawn(v[0])) { std::printf("FATAL: SpawnHub Fan.\n"); return 1; }
    P2PeerConWsa* pSvc = P2PeerConWsa::ServiceFactory(L"Fan.*", kFanPort);
    if (!pSvc) { std::printf("FATAL: ServiceFactory.\n"); return 1; }
    v[0].hub->PostP2PeerCon(pSvc);
    Sleep(500);

    // Children one at a time, each logged in before the next connects, so the
    // hub's list order is the order below (S first, R[C-1] last).
    clk::time_point tc = clk::now();
    for (size_t i = 1; i < v.size(); ++i)
    {
        long want = g_acks.load() + 1;
        if (!Spawn(v[i])) { std::printf("FATAL: SpawnHub %s.\n", N(v[i].addr).c_str()); return 1; }
        P2PeerConWsa* pCli = P2PeerConWsa::ClientFactory(L"Fan", L"127.0.0.1", kFanPort);
        if (!pCli) { std::printf("FATAL: ClientFactory.\n"); return 1; }
        v[i].hub->PostP2PeerCon(pCli);
        if (!WaitAtLeast(g_acks, want, 15000))
        { std::printf("TIMEOUT: %s never logged in.\n", N(v[i].addr).c_str()); return 3; }
    }
    std::printf("all %zu children logged in (%.0f ms)  link: authed=%d trust=%d cypher=%d\n\n",
                v.size() - 1, perf::NsSince(tc) / 1e6, g_nAuthed.load(), g_nTrust.load(), g_nCypher.load());
    if (post.bAuth && !post.bOpen && g_nAuthed.load() != 1)
    { std::printf("FATAL: posture %c asked for an authenticated link and did not get one.\n", post.cTag); return 1; }
    std::fflush(stdout);

    Node& S = v[1];
    const std::wstring& first = v[2].addr;
    const std::wstring& last  = v.back().addr;
    std::string param = "C=" + std::to_string(C);

    // warm-up both ends
    { long b = g_recv.load();
      for (int i = 0; i < 100; ++i) { Post(*S.hub, S.addr, first, body); Post(*S.hub, S.addr, last, body); }
      if (!WaitAtLeast(g_recv, b + 200, 10000)) { std::printf("TIMEOUT: warm-up.\n"); return 3; } }

    if (!Latency("lat_first", param, S, first, body, K)) return 3;
    if (!Latency("lat_last",  param, S, last,  body, K)) return 3;
    if (!Throughput("thr_last", param, S, last, body, Nmsg)) return 3;

    // all: one message to every receiver, the round timed until all arrive
    {
        long rounds = std::max<long>(5, 4000 / C);
        std::vector<double> us; us.reserve((size_t)rounds);
        double cpu0 = perf::CpuNow();
        unsigned long long a0 = perf::Allocs();
        for (long r = 0; r < rounds; ++r)
        {
            long target = g_recv.load() + C;
            clk::time_point t0 = clk::now();
            for (size_t i = 2; i < v.size(); ++i) Post(*S.hub, S.addr, v[i].addr, body);
            if (!WaitAtLeast(g_recv, target, 60000)) { std::printf("TIMEOUT: all round %ld.\n", r); return 3; }
            us.push_back(perf::NsSince(t0) / 1e3);
        }
        double nMsg = (double)rounds * C;
        char note[96]; std::snprintf(note, sizeof note, "one round = %ld messages; cpu and allocs per message", C);
        perf::Report("perf_fanout", "all_round", param + g_tag, "us", perf::Summarise(us),
                     (perf::CpuNow() - cpu0) * 1e6 / nMsg,
                     perf::AllocsCounted() ? (double)(perf::Allocs() - a0) / nMsg : -1, note, "us/msg");
    }
    return 0;
}

// =============================================================================
static int RunChain(long H, long K, long Nmsg, const std::vector<unsigned char>& body)
{
    std::printf("topology: chain of %ld hops (%ld hubs, %ld relays), %s\n\n",
                H, H + 1, H - 1, g_bDmx ? "Dmx" : "Wsa loopback");
    std::vector<Node> v((size_t)H + 1);
    CloseAll guard{v};
    v[0].addr = L"Ch";
    for (long k = 1; k <= H; ++k)
    { wchar_t b[16]; std::swprintf(b, 16, L".L%ld", k); v[(size_t)k].addr = v[(size_t)k - 1].addr + b; }

    std::vector<std::wstring> vAll; for (auto& n : v) vAll.push_back(n.addr);
    const Posture& post = *g_pPost;
    if ((post.bAuth || post.bAttest || post.bSeal) && !Provision(vAll))
    { std::printf("FATAL: key provisioning failed.\n"); return 1; }

    for (long k = 0; k <= H; ++k)
    {
        Role r = k == 0 ? RoleDest : k == H ? RoleOrigin : RoleRelay;
        v[(size_t)k].hub.reset(new FanHub(v[(size_t)k].addr, r));
        if (!ApplyPosture(*v[(size_t)k].hub, r))
        { std::printf("FATAL: posture %c did not take on %s.\n", post.cTag, N(v[(size_t)k].addr).c_str()); return 1; }
    }

    // Root first; each hub listens for its one child, then the child connects.
    std::vector<std::wstring> vSvc((size_t)H + 1);
    if (!Spawn(v[0])) { std::printf("FATAL: SpawnHub Ch.\n"); return 1; }
    for (long k = 1; k <= H; ++k)
    {
        Node& parent = v[(size_t)k - 1];
        Node& child  = v[(size_t)k];
        wchar_t b[32]; std::swprintf(b, 32, L"PerfFan.L%ld", k); vSvc[(size_t)k] = b;
        short port = (short)(kChainPort + k - 1);
        P2PeerCon* pSvc = g_bDmx
            ? (P2PeerCon*)P2PeerConDmx::ServiceFactory(child.addr.c_str(), vSvc[(size_t)k].c_str())
            : (P2PeerCon*)P2PeerConWsa::ServiceFactory(child.addr.c_str(), port);
        if (!pSvc) { std::printf("FATAL: ServiceFactory hop %ld.\n", k); return 1; }
        parent.hub->PostP2PeerCon(pSvc);
        Sleep(300);
        long want = g_acks.load() + 1;
        if (!Spawn(child)) { std::printf("FATAL: SpawnHub %s.\n", N(child.addr).c_str()); return 1; }
        P2PeerCon* pCli = g_bDmx
            ? (P2PeerCon*)P2PeerConDmx::ClientFactory(parent.addr.c_str(), vSvc[(size_t)k].c_str())
            : (P2PeerCon*)P2PeerConWsa::ClientFactory(parent.addr.c_str(), L"127.0.0.1", port);
        if (!pCli) { std::printf("FATAL: ClientFactory hop %ld.\n", k); return 1; }
        child.hub->PostP2PeerCon(pCli);
        if (!WaitAtLeast(g_acks, want, 15000))
        { std::printf("TIMEOUT: %s never logged in.\n", N(child.addr).c_str()); return 3; }
    }
    std::printf("chain up  link: authed=%d trust=%d cypher=%d\n", g_nAuthed.load(), g_nTrust.load(), g_nCypher.load());
    if (post.bSeal)
        std::printf("NOTE: the seal is waived on the last hop; %s\n",
                    H >= 2 ? "H>=2, so the origin seals and Ch opens." : "H=1, so this row does C's work.");
    std::printf("\n");
    if (post.bAuth && !post.bOpen && g_nAuthed.load() != 1)
    { std::printf("FATAL: posture %c asked for an authenticated link and did not get one.\n", post.cTag); return 1; }
    std::fflush(stdout);

    Node& O = v.back();
    const std::wstring& dst = v[0].addr;
    std::string param = "H=" + std::to_string(H);

    { long b = g_recv.load();
      for (int i = 0; i < 200; ++i) Post(*O.hub, O.addr, dst, body);
      if (!WaitAtLeast(g_recv, b + 200, 20000)) { std::printf("TIMEOUT: warm-up.\n"); return 3; } }

    if (!Latency("lat", param, O, dst, body, K)) return 3;
    if (!Throughput("thr", param, O, dst, body, Nmsg)) return 3;
    return 0;
}

// =============================================================================
int main(int argc, char* argv[])
{
    std::string mode = argc > 1 ? argv[1] : "";
    long size = argc > 2 ? std::atol(argv[2]) : 0;
    long K    = argc > 3 ? std::atol(argv[3]) : 1000;
    long Nmsg = argc > 4 ? std::atol(argv[4]) : 20000;
    long payload = perf::EnvLong("PERF_PAYLOAD", 64);
    if ((mode != "fan" && mode != "chain") || size < 1 ||
        (mode == "fan" && size > 250) || (mode == "chain" && size > 16) || K < 1 || Nmsg < 1)
    {
        std::printf("usage: perf_fanout fan C [K] [N]     C = 1..250 receivers\n"
                    "       perf_fanout chain H [K] [N]   H = 1..16 hops\n");
        return 1;
    }
    if (const char* ps = std::getenv("PERF_POSTURE"); ps && *ps)
    {
        g_pPost = nullptr;
        for (const Posture& p : kPost) if (p.cTag == (char)std::toupper((unsigned char)*ps)) g_pPost = &p;
        if (!g_pPost) { std::printf("FATAL: PERF_POSTURE=%s (want A..E or L).\n", ps); return 1; }
    }
    if (const char* ts = std::getenv("PERF_TRANSPORT"); ts && *ts)
    {
        std::string t = ts;
        if (t == "dmx") g_bDmx = true;
        else if (t != "wsa") { std::printf("FATAL: PERF_TRANSPORT=%s (want wsa|dmx).\n", ts); return 1; }
        if (g_bDmx && mode == "fan") { std::printf("FATAL: fan is Wsa only (see the header).\n"); return 1; }
    }

    perf::PrintBox("perf_fanout");
    std::printf("mode=%s size=%ld K=%ld N=%ld payload=%ldB posture=%c (%s) transport=%s\n",
                mode.c_str(), size, K, Nmsg, payload, g_pPost->cTag, g_pPost->pszName,
                g_bDmx ? "dmx" : "wsa");
    if (const char* k = std::getenv("PERF_KEEP"); k && *k)
        std::printf("PERF_KEEP=%s: those switches stay at their default (true)\n", k);
    g_tag = std::string("/") + g_pPost->cTag + "/" + (g_bDmx ? "dmx" : "wsa");
    if (const char* k = std::getenv("PERF_KEEP"); k && *k) g_tag += std::string("/keep=") + k;
    if (const char* w = std::getenv("PERF_WAIVE"); w && std::strcmp(w, "0") == 0)
    {
        g_tag += "/waive=0";
        std::printf("PERF_WAIVE=0: WaiveEndToEndInProcess(false), the pre-3.6.0 default\n");
    }
    std::fflush(stdout);

    std::vector<unsigned char> body((size_t)std::max<long>(1, payload));
    for (size_t i = 0; i < body.size(); ++i) body[i] = (unsigned char)('a' + i % 26);
    g_cbBody = body.size();

    RaiseFdLimit();
    if (!StartupP2Pmsg(MAX_P2PmsgHub)) { std::printf("FATAL: StartupP2Pmsg failed.\n"); return 1; }
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);

    int nExit = 0;
    try
    {
        // RunFan/RunChain own their hubs; CloseAll closes them on every path.
        nExit = mode == "fan" ? RunFan(size, K, Nmsg, body) : RunChain(size, K, Nmsg, body);
    }
    catch (P2Pevent*) { std::printf("FATAL: P2Pevent thrown.\n"); nExit = 1; }

    if (!nExit && g_stray.load() != 0)
    { std::printf("FAIL: %ld messages delivered to a hub that was not their destination.\n", g_stray.load()); nExit = 1; }
    if (!nExit && g_badBody.load() != 0)
    { std::printf("FAIL: %ld delivered bodies had the wrong length.\n", g_badBody.load()); nExit = 1; }
    if (!nExit && g_frameN.load() > 0)
    {
        double avg = (double)g_frameBytes.load() / g_frameN.load();
        perf::Stats s; s.n = (size_t)g_frameN.load(); s.min = s.p50 = s.avg = s.p99 = s.max = avg;
        perf::Report("perf_fanout", "frame_bytes", std::to_string(payload) + "B" + g_tag, "B/msg", s);
    }

    CleanupP2Pmsg();
    WSACleanup();
    ScrubTemp();
    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
