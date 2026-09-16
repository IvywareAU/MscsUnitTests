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
// p2p_hubwake.cpp — PauseHub() must not be a one-way door.
//
// P2PeerHub::WakeupHub() ran `ASSERT(0); // Requires implementation` in its
// hub-context branch. Off the hub thread it re-signals correctly, so the three
// callers that exist -- p2peerhub_wakeup_hub() on the flat C surface, the
// service SERVICE_CONTROL_CONTINUE handler (P2PeerService::OnContinue) and a
// raw P2PsigHub_WAKEUP -- all reached the assert by the same route: signal the
// hub, hub pump dequeues P2PsigHub_WAKEUP, hub pump calls WakeupHub() on its
// own thread, assert. Debug aborted the process; Release returned silently.
// Either way a paused hub could never be resumed.
//
// Nothing exercised it. The one reference in the tree (TargetcoreSuite.cpp)
// passes a deliberately bogus handle, which p2peerhub_wakeup_hub() rejects
// before it reaches the hub at all, so the assert never fired in CI.
//
// WHAT IS BEING PROVEN
//
// PauseHub() latches ConState_CloseOnIdle on every connection and drops the
// ones already idle. WakeupHub() is the inverse of the latch: a connection
// still carrying traffic when the pause arrived keeps running. So the probe
// has to pause a connection that is BUSY -- pausing an idle one drops it, and
// no wakeup can recall it (documented, and not what this fixes).
//
// Hence the burst: the client posts kBurst messages and only then does main
// signal pause + wake. While that queue drains m_pP2PeerMsgSend is non-null,
// so the CLOSEONIDLE branch in P2PeerCon.cpp latches without dropping, and the
// WAKEUP branch that follows clears the bit again.
//
// Three assertions, in order of what they catch:
//   1. every burst message arrives           -- pause/wake loses no traffic
//   2. the SAME connection is still there,
//      GetState(ConState_CloseOnIdle) == 0   -- the latch was actually cleared
//   3. a message posted AFTER the wake lands  -- the hub is operational again
//
// MEASURED against the old code (Release, five runs, 2026-08-18): the test
// fails every time, at assertion 1 in four runs and assertion 3 in one.
//
//   assertion 1, "only 1999 of 2000 burst messages arrived" -- the sharper
//     result, and not the one expected. Leaving the latch set does not merely
//     close the connection once the queue empties: the drop lands while the
//     tail of the burst is still in flight and takes a message with it. The old
//     WakeupHub cost delivery, not just resumability.
//   assertion 3, when the drop happens to land after the last message clears --
//     the post-wake message finds no connection, because the default
//     ON_P2PeerCon_CLOSE handler restarts a CLIENT only after m_uAutoRestart
//     (20s), well past this wait.
//
// Assertion 2 does NOT discriminate, and the conID check does not rescue it:
// Restart() reuses the same P2PeerCon object, so the ID is stable across a
// drop-and-restart and the state bits are clear again by the time it is read.
// It is kept because it checks the latch directly in the case that matters --
// the fixed one, where the connection genuinely never dropped -- not because it
// catches the regression. Assertions 1 and 3 do that.
//
// Verdict = process EXIT CODE:  0 SUCCESS | 1 SETUP | 2 FAILED | 3 TIMEOUT

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>

// --- narrow-print helper (portable; no wide stdio) -------------------------
static std::string N(const wchar_t* w)
{
    std::string s;
    if (w) for (; *w; ++w) {
        unsigned long c = (unsigned long)*w;
        s.push_back(c < 0x80 ? (char)c : '?');
    }
    return s;
}
static void Log(const char* role, const char* msg)
{
    std::printf("[%s] %s\n", role, msg);
    std::fflush(stdout);
}

// -------------------------------------------------------------------------
static const short      kTestPort   = 7833;
static const P2PaddrSTR kServerAddr = L"HubWake.Server";
static const P2PaddrSTR kClientAddr = L"HubWake.Client";

// Big enough that the send queue is still draining when the pause signal
// arrives -- that is the whole point, see the header comment. 2000 x 2KB.
static const int        kBurst      = 2000;
static const size_t     kPayload    = 2048;

// The single message posted after the wake, recognised by its own tag.
static LPCWSTR          kAfterTag   = L"AFTER-WAKE";

static HANDLE            g_hBurstPosted = NULL;  // client -> main: burst is in flight
static HANDLE            g_hBurstDone   = NULL;  // server -> main: all kBurst arrived
static HANDLE            g_hAfterSeen   = NULL;  // server -> main: post-wake msg arrived
static std::atomic<int>  g_nReceived(0);

// =========================================================================
class WakeHub : public P2PeerHub
{
public:
    WakeHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr), m_bServer(bServer), m_bSent(false) {}
    virtual ~WakeHub() {}

    // Posted by main once the pause/wake round trip has been signalled.
    void PostAfterWake()
    {
        P2Psize_t nBytes = (P2Psize_t)((wcslen(kAfterTag) + 1) * sizeof(wchar_t));
        PostP2PeerMsg(new P2PeerMsg32(
            kClientAddr, kServerAddr, P2Pmsg_BCast, kAfterTag, nBytes));
    }

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        if (m_bServer && pMsg && pMsg->Data() && pMsg->DataSize() > 0)
        {
            // The post-wake message is the only one carrying the tag.
            //   THE PAYLOAD POINTER IS NOT ALIGNED and must be copied out
            // before it is read as wchar_t: Data() addresses bytes inside a
            // pack(1) image, so it starts at an arbitrary offset. This line
            // did NOT fail the Linux sanitiser run of 2026-08-22 - its payload
            // happened to land aligned - which is exactly why it is fixed
            // here rather than left for the day it moves. Same defect as the
            // seven F-S4-3 names; this test was not one of them.
            const size_t cbTag  = wcslen(kAfterTag) * sizeof(wchar_t);
            const size_t cbHave = (size_t)pMsg->DataSize();
            std::wstring wLead(wcslen(kAfterTag), L'\0');
            if (cbHave >= cbTag && !wLead.empty())
              std::memcpy(&wLead[0], pMsg->Data(), cbTag);
            if (cbHave >= cbTag && wcsncmp(wLead.c_str(), kAfterTag, wcslen(kAfterTag)) == 0)
            {
                Log("SERVER", "post-wake message received");
                if (g_hAfterSeen) SetEvent(g_hAfterSeen);
                return msgHANDLED;
            }
            if (g_nReceived.fetch_add(1) + 1 == kBurst)
            {
                Log("SERVER", "full burst received");
                if (g_hBurstDone) SetEvent(g_hBurstDone);
            }
        }
        return msgHANDLED;
    }

    virtual conRESULT On_ConLoginAck(P2PeerCon*  pCon,
                                     P2PaddrSTR  strThisP2Paddr,
                                     P2PaddrSTR  strThatP2Paddr,
                                     const void* pvLoginAck,
                                     P2Psize_t   iSize) override
    {
        conRESULT result = P2PeerHub::On_ConLoginAck(
                               pCon, strThisP2Paddr, strThatP2Paddr, pvLoginAck, iSize);
        if (!m_bServer && !m_bSent)
        {
            m_bSent = true;
            PostBurst();
            if (g_hBurstPosted) SetEvent(g_hBurstPosted);
        }
        return result;
    }

private:
    void PostBurst()
    {
        // Payload content is irrelevant; only its size matters, and it must not
        // begin with kAfterTag or the server would count it as the post-wake
        // message. A run of 'b' cannot collide.
        wchar_t* pBuf = new wchar_t[kPayload / sizeof(wchar_t)];
        for (size_t i = 0; i < kPayload / sizeof(wchar_t); ++i) pBuf[i] = L'b';
        pBuf[kPayload / sizeof(wchar_t) - 1] = 0;

        for (int i = 0; i < kBurst; ++i)
            PostP2PeerMsg(new P2PeerMsg32(
                kClientAddr, kServerAddr, P2Pmsg_BCast, pBuf, (P2Psize_t)kPayload));

        delete [] pBuf;
        std::printf("[CLIENT] posted burst of %d x %u bytes\n",
                    kBurst, (unsigned)kPayload);
        std::fflush(stdout);
    }

private:
    bool m_bServer;
    bool m_bSent;
};

// =========================================================================
int main(int /*argc*/, char* /*argv*/[])
{
    std::printf("=== p2p_hubwake - PauseHub()/WakeupHub() round trip ===\n");
    std::printf("Port : %d (127.0.0.1), burst %d x %u bytes\n\n",
                (int)kTestPort, kBurst, (unsigned)kPayload);
    std::fflush(stdout);

    g_hBurstPosted = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hBurstDone   = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hAfterSeen   = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16))
    {
        std::printf("FATAL: StartupP2Pmsg() failed.\n");
        return 1;
    }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);

    // ---- Hub A: SERVER ----------------------------------------------------
    WakeHub oServer(kServerAddr, /*bServer*/ true);
    oServer.RequireAuth ( false );
    HANDLE hServerThread = oServer.SpawnHub();
    if (!hServerThread) { std::printf("FATAL: server SpawnHub failed.\n"); return 1; }

    P2PeerConWsa* pSvcCon = P2PeerConWsa::ServiceFactory(kClientAddr, kTestPort);
    if (!pSvcCon) { std::printf("FATAL: ServiceFactory failed.\n"); return 1; }
    oServer.PostP2PeerCon(pSvcCon);
    Log("SERVER", "listening");

    Sleep(750);                            // bind + listen before the client dials

    // ---- Hub B: CLIENT ----------------------------------------------------
    WakeHub oClient(kClientAddr, /*bServer*/ false);
    oClient.RequireAuth ( false );
    HANDLE hClientThread = oClient.SpawnHub();
    if (!hClientThread) { std::printf("FATAL: client SpawnHub failed.\n"); return 1; }

    P2PeerConWsa* pCliCon = P2PeerConWsa::ClientFactory(kServerAddr, L"127.0.0.1", kTestPort);
    if (!pCliCon) { std::printf("FATAL: ClientFactory failed.\n"); return 1; }
    oClient.PostP2PeerCon(pCliCon);
    Log("CLIENT", "dialling");

    if (WaitForSingleObject(g_hBurstPosted, 15000) != WAIT_OBJECT_0)
    {
        Log("MAIN", "TIMEOUT - handshake never completed, burst not posted");
        return 3;
    }

    // Identify the connection before the pause, so assertion 2 is at least
    // talking about a specific connection rather than any connection to the
    // address. Note this does not detect a drop-and-restart: Restart() reuses
    // the object and the ID with it. See the header comment.
    P2PconID nConIDBefore = 0;
    {
        SafeP2PeerCon oSafeCon;
        if (oClient.ConQuery(kServerAddr, oSafeCon) && (P2PeerCon*)oSafeCon != 0)
            nConIDBefore = ((P2PeerCon*)oSafeCon)->GetP2PconID();
    }
    if (nConIDBefore == 0)
    {
        Log("MAIN", "SETUP - no client connection to identify before the pause");
        return 1;
    }
    std::printf("[MAIN] connection before pause: conID=%u\n", (unsigned)nConIDBefore);
    std::fflush(stdout);

    // ---- The thing under test --------------------------------------------
    // Both calls come from MAIN, i.e. off the hub thread, which is the route
    // every real caller takes: SignalP2PmsgHub -> hub pump -> {Pause,Wakeup}Hub
    // on the hub's own thread. That inner call is where the assert used to be.
    Log("MAIN", "PauseHub() on the client hub, connection busy");
    oClient.PauseHub();
    Log("MAIN", "WakeupHub() on the client hub");
    oClient.WakeupHub();

    int nExit = 0;

    // ---- 1. no traffic lost across the pause/wake -------------------------
    if (WaitForSingleObject(g_hBurstDone, 30000) != WAIT_OBJECT_0)
    {
        std::printf("[MAIN] FAILED (1) - only %d of %d burst messages arrived\n",
                    g_nReceived.load(), kBurst);
        std::fflush(stdout);
        nExit = 2;
    }
    else
        Log("MAIN", "OK (1) - whole burst survived the pause/wake");

    // ---- 2. THAT connection survived and the latch is clear ---------------
    // Read through the hub's own lookup rather than a retained raw pointer, so a
    // connection the pause dropped shows up as absent rather than as a dangling
    // read; then check the ID, so a restarted replacement is not mistaken for a
    // survivor.
    {
        SafeP2PeerCon oSafeCon;
        if (!oClient.ConQuery(kServerAddr, oSafeCon) || (P2PeerCon*)oSafeCon == 0)
        {
            Log("MAIN", "FAILED (2) - connection did not survive the pause");
            nExit = 2;
        }
        else
        {
            P2PconID nConIDAfter = ((P2PeerCon*)oSafeCon)->GetP2PconID();
            DWORD    dwIdle      = ((P2PeerCon*)oSafeCon)->GetState(ConState_CloseOnIdle);
            if (nConIDAfter != nConIDBefore)
            {
                std::printf("[MAIN] FAILED (2) - connection was replaced, conID %u -> %u "
                            "(the pause dropped it and the close handler restarted it)\n",
                            (unsigned)nConIDBefore, (unsigned)nConIDAfter);
                std::fflush(stdout);
                nExit = 2;
            }
            else if (dwIdle != 0)
            {
                Log("MAIN", "FAILED (2) - ConState_CloseOnIdle still latched after wakeup");
                nExit = 2;
            }
            else
                Log("MAIN", "OK (2) - same connection up, close-on-idle cleared");
        }
    }

    // ---- 3. the hub is operational again ----------------------------------
    if (nExit == 0)
    {
        oClient.PostAfterWake();
        if (WaitForSingleObject(g_hAfterSeen, 15000) != WAIT_OBJECT_0)
        {
            Log("MAIN", "FAILED (3) - message posted after the wake never arrived");
            nExit = 2;
        }
        else
            Log("MAIN", "OK (3) - hub carries traffic posted after the wake");
    }

    // ---- Shutdown ---------------------------------------------------------
    Log("MAIN", "shutdown begin");
    oClient.CloseHub();
    oServer.CloseHub();
    WaitForSingleObject(hClientThread, 5000);
    WaitForSingleObject(hServerThread, 5000);
    CloseHandle(hClientThread);
    CloseHandle(hServerThread);

    CleanupP2Pmsg();
    if (g_hBurstPosted) CloseHandle(g_hBurstPosted);
    if (g_hBurstDone)   CloseHandle(g_hBurstDone);
    if (g_hAfterSeen)   CloseHandle(g_hAfterSeen);
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
