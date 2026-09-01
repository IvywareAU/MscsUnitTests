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
// teardown_stress.cpp — mid-flight connection kill/teardown stress (LinuxPortPlan §8, §5.6).
//
// The §8 "Teardown/cancel" line: "N connections, kill/close mid-flight x 10^3 iterations
// under ASan — validates §5.6 and the AddRef/Release protocol." This is where io_uring
// teardown differs most sharply from IOCP: on Windows CloseHandle(socket) auto-completes
// pending ops with ERROR_OPERATION_ABORTED; on Linux close(fd) does NOT cancel in-flight
// io_uring ops, so the shim must io_uring_prep_cancel_fd(IORING_ASYNC_CANCEL_ALL) on the
// owning ring, let each op surface as -ECANCELED -> ERROR_OPERATION_ABORTED, and close only
// after the association is dropped (§5.6). Refcount leaks / underflows in the con
// AddRef/Release protocol and use-after-free on the cancellation path hide exactly here.
//
// STATUS: a built diagnostic, run manually via run_sanitizers.sh (not a ctest gate).
// Run under ASan it found + drove the fix of five real, pre-existing teardown/lifetime bugs
// (stack-use-after-return posting a stack-local P2Paddr; three new[]/delete mismatches on the
// recv/hub-array buffers; the P2PmsgPump + its io_uring ring leaked per hub -> ENOMEM; a
// SignalP2PmsgHub-vs-pump-destroy lock race), and then the §5.1 ConnectExThread->io_uring-
// connect rework that removed the last teardown crash (the detached blocking-connect helper
// used to outlive its con/ring under a mid-connect kill; the Wsa connect now goes through
// native io_uring prep_connect, cancelled by cancel_fd on teardown). The full 1000-connection
// churn now completes and is memory-SAFE under ASan.
//
// §5.6 FOLLOW-UP (this workstream) — all three teardown-robustness leaks/abort are now FIXED;
// the full 1000-connection churn is ZERO-leak clean under ASan (detect_leaks=1, no UAF):
//   (1) The uncaught-P2Pevent abort. P2PeerHub::ProcHub / P2PeerExplorer::ProcExpump (the hub/
//       explorer thread trampolines) ran CreateP2PmsgHub()/RunHub()/CloseP2PmsgHub() with NO
//       exception boundary, so a P2Pevent thrown by hub setup or the teardown-drain under
//       socket/port pressure escaped the pump thread and terminated the process. Both now wrap
//       the body in try/catch(...)->Cancel(), matching the already-guarded ProcPump.
//   (2) The P2PmsgHubMgr critical section (~P2PmsgHubMgr now DeleteCriticalSection()s the
//       m_oCSection its ctor initialised) and the transient control/Signal OVERLAPPEDs (RunHub
//       posts a P2PsigCon_DESTROY OVERLAPPED per con on close; CloseP2PmsgHub's drain now
//       DrainOVERLAPPED()s each completion, freeing the throw-away objects the bypassed live
//       pump would have freed).
//   (3) The bulk mid-flight con leak (~200 cons + their buffers). ROOT CAUSE was TWO bugs in
//       CloseP2PmsgHub's drain: (a) a cancelled op completes with ERROR_OPERATION_ABORTED, for
//       which GetQueuedCompletionStatus returns FALSE but STILL yields its OVERLAPPED - the old
//       `while(GQCS(...))` treated that as "no completion" and STOPPED at the first cancelled
//       con op, so the con's cancelled recv/connect was never drained and its OVERLAPPED ref
//       never Release()d (refcount stuck at 1, con leaked). The drain now loops on lpOverlapped
//       (null == genuinely no more completions) so it processes cancellations too. (b) On Linux
//       CloseHandle(fd) already erased the io_uring fd->key assoc, so that cancelled completion
//       comes back KEYLESS; the owning con is now recovered from the OVERLAPPEDcon's stable
//       pOwnerCon (set at MakeOVERLAPPED) - safe because the in-flight OVL still holds the ref
//       we are about to release, so the con is alive. (An earlier attempt to stamp the key onto
//       the OVERLAPPED at submit was reverted: without fix (a) it changed nothing, and it also
//       risked stale-key UAF via fd reuse; the OVL-owned back-pointer has neither problem.)
//
// TSan (run_sanitizers.sh thread) — the churn is now ALL SANITIZERS CLEAN (0 races). A cascade
// of five pre-existing cross-thread races was fixed: (1) P2PeerConPlc m_cRef/m_bDestroy atomic +
// Release() deletes off the returned decrement value; (2) the s_cP2Pmsg counter atomic; (3)
// P2PeerHub::m_nHubID (a CloseHub<->RunHub spin-wait completion flag) wrapped in std::atomic_ref
// at its cross-thread accesses (it can't be a plain atomic member - CreateThread writes it via a
// raw DWORD*); (4) the g_P2PeerMsgInstances counter atomic; (5) the pump signal queue
// m_oCListP2PsigID given one consistent lock (m_oCSection) - SignalP2PmsgPump now takes it and
// PumpP2Pmsg reads via locked SigCount()/SigPop(). teardown_stress is now clean under BOTH ASan
// and TSan (run_sanitizers.sh runs both).
//
// Strategy: ONE persistent server hub with a wildcard-domain Wsa service listener stays up
// for the whole run; client hubs are spun up in small concurrent batches, each dials the
// server, and after a per-batch VARYING sub-handshake delay every client hub is torn down.
// The delay sweeps 0..maxDelayMs so teardown lands at every phase, cancelling real in-flight
// connect/recv ops on both the client ring (destroyed) and the server ring.
//
// Verdict = process EXIT CODE: 0 SUCCESS (all batches ran, server survived) | 1 SETUP.
// The REAL signal is sanitizer cleanliness (a report aborts non-zero).
//
// Usage: teardown_stress [total_connections] [concurrency] [max_delay_ms]
//        defaults: 200 4 8   (run 1000 8 12 by hand under a sanitizer)
//
// Build (Linux, plain):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore -I../TargetCore \
//       -I../Platform -I../Platform/win-compat teardown_stress.cpp \
//       -L../build/TargetCore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/TargetCore -Wl,-rpath,../build/Msgcore -o teardown_stress
// Under ASan/TSan: run_sanitizers.sh rebuilds the libs + harness with -fsanitize.

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
#include <atomic>
#include <vector>
#include <memory>

// ---- global counters (touched from pump threads; atomic) ------------------
static std::atomic<int> g_nServerAccept{0};
static std::atomic<int> g_nServerLoginAck{0};
static std::atomic<int> g_nServerClose{0};
static std::atomic<int> g_nClientLoginAck{0};

static const short      kPort        = 7802;                 // distinct from wsa_mesh (7801)
static const P2PaddrSTR kServerAddr  = L"Stress.Server";
static const P2PaddrSTR kServerDomat = L"*";                 // wildcard: accept any client
static const P2PaddrSTR kClientDomat = L"Stress.Server";     // client expects the server

// =========================================================================
// A hub that merely counts the lifecycle callbacks it forwards to the base.
class StressHub : public P2PeerHub
{
public:
    StressHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr), m_bServer(bServer) {}
    virtual ~StressHub() {}

protected:
    virtual conRESULT On_ConAccept(P2PeerCon* pCon) override
    {
        if (m_bServer) g_nServerAccept.fetch_add(1, std::memory_order_relaxed);
        return P2PeerHub::On_ConAccept(pCon);
    }
    virtual conRESULT On_ConLoginAck(P2PeerCon*  pCon,
                                     P2PaddrSTR  strThisP2Paddr,
                                     P2PaddrSTR  strThatP2Paddr,
                                     const void* pvLoginAck,
                                     P2Psize_t   iSize) override
    {
        if (m_bServer) g_nServerLoginAck.fetch_add(1, std::memory_order_relaxed);
        else           g_nClientLoginAck.fetch_add(1, std::memory_order_relaxed);
        return P2PeerHub::On_ConLoginAck(pCon, strThisP2Paddr, strThatP2Paddr,
                                         pvLoginAck, iSize);
    }
    virtual conRESULT On_ConClose(P2PeerCon* pCon) override
    {
        if (m_bServer) g_nServerClose.fetch_add(1, std::memory_order_relaxed);
        return P2PeerHub::On_ConClose(pCon);
    }

private:
    bool m_bServer;
};

// A client hub + its dialing connection, torn down together.
struct ClientNode
{
    std::unique_ptr<StressHub> hub;
    HANDLE                     thread = NULL;
};

static void Log(const char* msg) { std::printf("%s\n", msg); std::fflush(stdout); }

// =========================================================================
int main(int argc, char* argv[])
{
    const int nTotal   = (argc > 1) ? std::atoi(argv[1]) : 200;
    const int nConc    = (argc > 2) ? std::atoi(argv[2]) : 4;
    const int nMaxDlyMs= (argc > 3) ? std::atoi(argv[3]) : 8;
    const int nConcClamped = (nConc < 1) ? 1 : nConc;

    std::printf("=== teardown_stress: %d connections, concurrency %d, "
                "delay sweep 0..%dms, port %d ===\n",
                nTotal, nConcClamped, nMaxDlyMs, (int)kPort);
    std::fflush(stdout);

    if (!StartupP2Pmsg(16)) { Log("FATAL: StartupP2Pmsg() failed."); return 1; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);   // no-op shim on Linux

    // ---- persistent server: hub + wildcard Wsa service listener -----------
    StressHub oServer(kServerAddr, /*bServer*/ true);
    oServer.RequireAuth ( false );
    HANDLE hServerThread = oServer.SpawnHub();
    if (!hServerThread) { Log("FATAL: server SpawnHub failed."); return 1; }

    P2PeerConWsa* pSvcCon = P2PeerConWsa::ServiceFactory(kServerDomat, kPort);
    if (!pSvcCon) { Log("FATAL: server ServiceFactory failed."); return 1; }
    oServer.PostP2PeerCon(pSvcCon);
    Sleep(750);   // let the listener bind + listen before the first dial
    Log("server listening; beginning client churn...");

    // ---- churn client hubs in concurrent batches --------------------------
    int nMade = 0, nBatch = 0;
    while (nMade < nTotal)
    {
        int nThis = nConcClamped;
        if (nMade + nThis > nTotal) nThis = nTotal - nMade;

        std::vector<ClientNode> batch;
        batch.reserve(nThis);
        for (int i = 0; i < nThis; ++i)
        {
            // Unique address per client so completed logins never collide.
            wchar_t addr[64];
            swprintf(addr, 64, L"Stress.Client.%d", nMade + i);

            ClientNode node;
            node.hub = std::make_unique<StressHub>(addr, /*bServer*/ false);
            node.hub->RequireAuth ( false );
            node.thread = node.hub->SpawnHub();
            if (node.thread)
            {
                P2PeerConWsa* pCli =
                    P2PeerConWsa::ClientFactory(kClientDomat, L"127.0.0.1", kPort);
                if (pCli) node.hub->PostP2PeerCon(pCli);
            }
            batch.push_back(std::move(node));
        }

        // Vary the kill delay across the whole sub-handshake window so teardown
        // lands at connect-not-yet-submitted (0ms) through post-login (maxDelay).
        int dly = (nMaxDlyMs <= 0) ? 0 : (nBatch * 3) % (nMaxDlyMs + 1);
        if (dly) Sleep(dly);

        // Tear the whole batch down mid-flight.
        for (auto& node : batch)
            if (node.hub) node.hub->CloseHub();
        for (auto& node : batch)
            if (node.thread) { WaitForSingleObject(node.thread, 3000);
                               CloseHandle(node.thread); }
        // batch (and its unique_ptr hubs) destruct here.

        nMade += nThis;
        ++nBatch;
        if (nBatch % 25 == 0)
        {
            std::printf("  ... %d/%d connections churned "
                        "(srv accept=%d ack=%d close=%d; cli ack=%d)\n",
                        nMade, nTotal,
                        g_nServerAccept.load(), g_nServerLoginAck.load(),
                        g_nServerClose.load(), g_nClientLoginAck.load());
            std::fflush(stdout);
        }
    }

    // ---- tear the persistent server down (ring destruction drain, §5.6) ----
    Log("client churn complete; shutting down server...");
    oServer.CloseHub();
    WaitForSingleObject(hServerThread, 5000);
    CloseHandle(hServerThread);

    CleanupP2Pmsg();
    WSACleanup();

    std::printf("=== SUCCESS: %d connections churned; "
                "server accept=%d loginAck=%d close=%d; client loginAck=%d ===\n",
                nTotal, g_nServerAccept.load(), g_nServerLoginAck.load(),
                g_nServerClose.load(), g_nClientLoginAck.load());
    std::fflush(stdout);
    return 0;
}
