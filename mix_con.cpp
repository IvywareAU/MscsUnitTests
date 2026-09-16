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
// mix_con.cpp — portable (Linux/Windows) MIXED-transport mesh probe (LinuxPortPlan §8/§9,
// Phase-4 exit "MixConTest green").
//
// Where TwoConTest asks "can one hub supervise two cons of the SAME transport", this asks
// the Phase-4 exit question: can ONE server hub, on ONE io_uring ring, concurrently
// supervise service connections of DIFFERENT transports and receive a BCast over each?
//
//   SERVER hub  -- P2PeerConWsa::ServiceFactory   (loopback TCP, io_uring accept/recv)
//               -- P2PeerConPipe::ServiceFactory  (AF_UNIX,      io_uring accept/recv)
//   2 CLIENT hubs, one per transport, each logs in and BCasts a payload.
//   SUCCESS = the server receives BOTH BCasts — proving the pump / io_uring layer is
//   transport-agnostic and handles heterogeneous fds (a TCP socket and an AF_UNIX socket,
//   with their distinct accept/connect paths) on one ring at once.
//
// (Historic note) Adding P2PeerConDmx to this mix once stalled the Dmx handshake
// intermittently. The cause was NOT a pump/eventfd "fold" (the pump already waits on the
// ring's GetQueuedCompletionStatus, and WaitForP2Pmsg/m_hQueEvent is dead code here): it was
// a TOCTOU in P2PeerConDmx::Connect(), which posted the accept-wake to the server before
// creating its own m_pOVERLAPPEDconnect, so the server's OnAccept() could observe a NULL
// connect-OVERLAPPED and silently skip firing On_ConConnect. Fixed by creating
// m_pOVERLAPPEDconnect before posting the accept (under g_oCSectP2PeerConDmx). The 3-way
// (Wsa+Pipe+Dmx) reproduction lives in mix_con3.cpp.
//
// Verdict = process EXIT CODE:  0 SUCCESS | 3 TIMEOUT | 1 SETUP.
//
// Build (Linux):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore -I../Targetcore \
//       -I../Msgcore/Platform -I../Msgcore/Platform/win-compat mix_con.cpp \
//       -L../build/Targetcore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/Targetcore -Wl,-rpath,../build/Msgcore -o mix_con

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerConPipe.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <atomic>

// --- narrow-print helpers (portable; no wide stdio) ------------------------
static std::string N(const wchar_t* w)
{
    std::string s;
    if (w) for (; *w; ++w) { unsigned long c = (unsigned long)*w; s.push_back(c < 0x80 ? (char)c : '?'); }
    return s;
}

//  THE PAYLOAD POINTER IS NOT ALIGNED, so it cannot be read as wchar_t in
//  place.  P2PeerMsg::Data() addresses the application bytes where they sit
//  inside the packed message image, and that image is pack(1) - a payload
//  begins at whatever offset the block headers and names ahead of it add up
//  to, which is odd about half the time.  Casting it to LPCWSTR is undefined
//  behaviour; on Linux, where wchar_t wants 4-byte alignment, it is what UBSan
//  reported as F-S4-3, at this very line.  Copy the bytes out into storage the
//  caller aligned - which is what the library's own wide accessors do
//  internally, and what P3PmsgData::c_vBlobCopy() offers as an accessor.
static std::string NBody(P2PeerMsg* pMsg)
{
    if (!pMsg || !pMsg->Data() || pMsg->DataSize() <= 0)
      return std::string("<no data>");
    const size_t cb = (size_t)pMsg->DataSize();
    std::wstring w(cb / sizeof(wchar_t), L'\0');
    if (!w.empty())
      std::memcpy(&w[0], pMsg->Data(), w.size() * sizeof(wchar_t));
    const size_t nNul = w.find(L'\0');        // the payloads are literals
    if (nNul != std::wstring::npos) w.resize(nNul);
    return N(w.c_str());
}
static void Log(const char* role, const char* msg)
{ std::printf("[%s] %s\n", role, msg); std::fflush(stdout); }

// -------------------------------------------------------------------------
static const short      kWsaPort     = 7811;
static LPCTSTR          kPipeName    = _T("\\\\.\\pipe\\P2PmixProbe");

static const P2PaddrSTR kServerAddr  = L"MixCon.Server";
static const P2PaddrSTR kWsaCliAddr  = L"MixCon.WsaClient";
static const P2PaddrSTR kPipeCliAddr = L"MixCon.PipeClient";

static const int        kExpected    = 2;      // one BCast per transport
static std::atomic<int> g_delivered{0};
static HANDLE           g_hDoneEvent = NULL;

// =========================================================================
//  One hub class, two roles. The server counts BCasts; each client fires its
//  own BCast once its login is acked.
// =========================================================================
class MixHub : public P2PeerHub
{
public:
    MixHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr), m_bServer(bServer), m_bSent(false),
          m_lpszMsg(nullptr) {}
    virtual ~MixHub() {}

    // client-side config: what to BCast once logged in
    void SetClientMessage(LPCWSTR lpszMsg) { m_lpszMsg = lpszMsg; }

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    { PrintMessage("BCast", pMsg); return msgHANDLED; }
    virtual msgRESULT On_P2PeerUCast(P2PeerMsg* pMsg) override
    { PrintMessage("UCast", pMsg); return msgHANDLED; }

    virtual conRESULT On_ConLoginAck(P2PeerCon*  pCon,
                                     P2PaddrSTR  strThisP2Paddr,
                                     P2PaddrSTR  strThatP2Paddr,
                                     const void* pvLoginAck,
                                     P2Psize_t   iSize) override
    {
        Trace("On_ConLoginAck", pCon);
        conRESULT result = P2PeerHub::On_ConLoginAck(
                               pCon, strThisP2Paddr, strThatP2Paddr, pvLoginAck, iSize);
        if (!m_bServer && !m_bSent && m_lpszMsg)
        {
            std::printf("[%s] login ack from '%s' - posting BCast.\n",
                        N(GetP2PaddrHub().c_wstr()).c_str(), N(strThatP2Paddr).c_str());
            std::fflush(stdout);
            PostTestMessage();
            m_bSent = true;
        }
        return result;
    }

    virtual conRESULT On_ConStartup(P2PeerCon* pCon) override
    { Trace("On_ConStartup", pCon); return P2PeerHub::On_ConStartup(pCon); }
    virtual conRESULT On_ConConnect(P2PeerCon* pCon) override
    { Trace("On_ConConnect", pCon); return P2PeerHub::On_ConConnect(pCon); }
    virtual conRESULT On_ConAccept(P2PeerCon* pCon) override
    { Trace("On_ConAccept", pCon); return P2PeerHub::On_ConAccept(pCon); }
    virtual conRESULT On_ConListen(P2PeerCon* pCon) override
    { Trace("On_ConListen", pCon); return P2PeerHub::On_ConListen(pCon); }
    virtual conRESULT On_ConLogin(P2PeerCon* pCon, P2PaddrSTR strThatP2Paddr,
                                  const void* pvLoginMsg, P2Psize_t iSize) override
    { Trace("On_ConLogin", pCon);
      return P2PeerHub::On_ConLogin(pCon, strThatP2Paddr, pvLoginMsg, iSize); }
    virtual conRESULT On_ConClose(P2PeerCon* pCon) override
    { Trace("On_ConClose", pCon); return P2PeerHub::On_ConClose(pCon); }
    virtual conRESULT On_ConShutdown(P2PeerCon* pCon) override
    { Trace("On_ConShutdown", pCon); return P2PeerHub::On_ConShutdown(pCon); }

private:
    void Trace(const char* lpszStage, P2PeerCon* pCon)
    {
        std::string addr = "<n/a>";
        try { if (pCon) addr = N((P2PaddrSTR)pCon->GetP2Paddress()); }
        catch (...) { addr = "<err>"; }
        std::printf("[%s] %-16s con=%p that='%s'\n",
                    m_bServer ? "SERVER" : "client", lpszStage, (void*)pCon, addr.c_str());
        std::fflush(stdout);
    }

    void PrintMessage(const char* lpszKind, P2PeerMsg* pMsg)
    {
        std::string src  = pMsg ? N(pMsg->GetSource()) : std::string("<null>");
        std::string data = NBody(pMsg);
        std::printf("\n[%s] %s from '%s':\n  > %s\n\n",
                    m_bServer ? "SERVER" : "client", lpszKind, src.c_str(), data.c_str());
        std::fflush(stdout);
        if (m_bServer)
        {
            int n = ++g_delivered;
            std::printf("[SERVER] deliveries: %d/%d\n", n, kExpected);
            std::fflush(stdout);
            if (n >= kExpected && g_hDoneEvent) SetEvent(g_hDoneEvent);
        }
    }

    void PostTestMessage()
    {
        P2Psize_t nBytes = (P2Psize_t)((wcslen(m_lpszMsg) + 1) * sizeof(wchar_t));
        P2PeerMsg32* pMsg = new P2PeerMsg32(
            GetP2PaddrHub().c_wstr(), kServerAddr, P2Pmsg_BCast, m_lpszMsg, nBytes);
        PostP2PeerMsg(pMsg);
        std::printf("[%s] Posted BCast: \"%s\"\n",
                    N(GetP2PaddrHub().c_wstr()).c_str(), N(m_lpszMsg).c_str());
        std::fflush(stdout);
    }

private:
    bool    m_bServer;
    bool    m_bSent;
    LPCWSTR m_lpszMsg;
};

// =========================================================================
int main(int /*argc*/, char* /*argv*/[])
{
    std::printf("=== mix_con - one hub, MIXED transports (Wsa + Pipe) ===\n\n");
    std::fflush(stdout);

    g_hDoneEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16)) { std::printf("FATAL: StartupP2Pmsg() failed.\n"); return 1; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);

    // ---- SERVER hub: one hub, two service cons of two transports ----------
    MixHub oServer(kServerAddr, /*bServer*/ true);
    oServer.RequireAuth ( false );
    HANDLE hServerThread = oServer.SpawnHub();
    if (!hServerThread) { std::printf("FATAL: server SpawnHub failed.\n"); return 1; }
    Log("SERVER", "hub thread started");

    P2PeerConWsa*  pSvcWsa  = P2PeerConWsa ::ServiceFactory(kWsaCliAddr,  kWsaPort);
    P2PeerConPipe* pSvcPipe = P2PeerConPipe::ServiceFactory(kPipeCliAddr, kPipeName);
    if (!pSvcWsa || !pSvcPipe) { std::printf("FATAL: a ServiceFactory failed.\n"); return 1; }
    oServer.PostP2PeerCon(pSvcWsa);
    oServer.PostP2PeerCon(pSvcPipe);
    Log("SERVER", "posted Wsa + Pipe service cons on ONE hub/ring");

    // Let the server arm both listeners before the clients dial.
    Sleep(1000);

    // ---- Two client hubs, one per transport -------------------------------
    MixHub oWsaCli(kWsaCliAddr, false);   oWsaCli .SetClientMessage(L"Hello via Wsa (loopback TCP)!");
    MixHub oPipeCli(kPipeCliAddr, false); oPipeCli.SetClientMessage(L"Hello via Pipe (AF_UNIX)!");

    oWsaCli.RequireAuth ( false );
    HANDLE hWsa  = oWsaCli .SpawnHub();
    oPipeCli.RequireAuth ( false );
    HANDLE hPipe = oPipeCli.SpawnHub();
    if (!hWsa || !hPipe) { std::printf("FATAL: a client SpawnHub failed.\n"); return 1; }

    oWsaCli .PostP2PeerCon(P2PeerConWsa ::ClientFactory(kServerAddr, L"127.0.0.1", kWsaPort));
    oPipeCli.PostP2PeerCon(P2PeerConPipe::ClientFactory(kServerAddr, kPipeName));
    Log("MAIN", "two clients dialing (Wsa / Pipe)");

    // ---- Wait for both BCasts --------------------------------------------
    Log("MAIN", "waiting up to 15s for 2 BCasts (one per transport)...");
    DWORD dwResult = WaitForSingleObject(g_hDoneEvent, 15000);

    int nExit;
    if (dwResult == WAIT_OBJECT_0)
    { Log("MAIN", "SUCCESS - server received a BCast over BOTH transports"); nExit = 0; }
    else
    {
        std::printf("[MAIN] TIMEOUT - only %d/%d BCasts delivered\n",
                    g_delivered.load(), kExpected);
        std::fflush(stdout);
        nExit = 3;
    }

    // ---- Shutdown --------------------------------------------------------
    Log("MAIN", "shutdown begin");
    oWsaCli.CloseHub(); oPipeCli.CloseHub();
    oServer.CloseHub();
    WaitForSingleObject(hWsa, 3000);
    WaitForSingleObject(hPipe, 3000); WaitForSingleObject(hServerThread, 3000);
    CloseHandle(hWsa); CloseHandle(hPipe); CloseHandle(hServerThread);

    CleanupP2Pmsg();
    if (g_hDoneEvent) { CloseHandle(g_hDoneEvent); g_hDoneEvent = NULL; }
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
