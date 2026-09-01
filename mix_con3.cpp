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
// mix_con3.cpp — 3-way MIXED-transport probe: Wsa + Pipe + Dmx on ONE server hub/ring.
//
// This is mix_con.cpp plus the P2PeerConDmx (in-process posted-completion) transport, to
// REPRODUCE + TRACE the deferred §5.4 "pump fold" stall: adding Dmx to the mix is reported
// to intermittently stall the Dmx handshake in multiples of the 8s RunHub pump timeout.
// Run it many times (it is fast when it works) to catch the intermittent stall; set
// P2P_IOCP_TRACE=1 / P2P_ERR_TRACE=1 for ring / framework tracing.
//
// Verdict = process EXIT CODE:  0 SUCCESS | 3 TIMEOUT | 1 SETUP.
//
// Build (Linux):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore -I../TargetCore \
//       -I../Platform -I../Platform/win-compat mix_con3.cpp \
//       -L../build/TargetCore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/TargetCore -Wl,-rpath,../build/Msgcore -o mix_con3

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerConPipe.h"
#include "P2PeerConDmx.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <atomic>

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

static const short      kWsaPort      = 7821;
static LPCTSTR          kPipeName     = _T("\\\\.\\pipe\\P2Pmix3Probe");
static LPCTSTR          kDmxService   = _T("P2Pmix3Dmx");

static const P2PaddrSTR kServerAddr   = L"Mix3.Server";
static const P2PaddrSTR kWsaCliAddr   = L"Mix3.WsaClient";
static const P2PaddrSTR kPipeCliAddr  = L"Mix3.PipeClient";
static const P2PaddrSTR kDmxCliAddr   = L"Mix3.DmxClient";

static const int        kExpected     = 3;      // one BCast per transport
static std::atomic<int> g_delivered{0};
static HANDLE           g_hDoneEvent = NULL;

class MixHub : public P2PeerHub
{
public:
    MixHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr), m_bServer(bServer), m_bSent(false), m_lpszMsg(nullptr) {}
    virtual ~MixHub() {}

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

int main(int /*argc*/, char* /*argv*/[])
{
    std::printf("=== mix_con3 - one hub, Wsa + Pipe + Dmx ===\n\n");
    std::fflush(stdout);

    g_hDoneEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16)) { std::printf("FATAL: StartupP2Pmsg() failed.\n"); return 1; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);

    MixHub oServer(kServerAddr, /*bServer*/ true);
    oServer.RequireAuth ( false );
    HANDLE hServerThread = oServer.SpawnHub();
    if (!hServerThread) { std::printf("FATAL: server SpawnHub failed.\n"); return 1; }
    Log("SERVER", "hub thread started");

    P2PeerConWsa*  pSvcWsa  = P2PeerConWsa ::ServiceFactory(kWsaCliAddr,  kWsaPort);
    P2PeerConPipe* pSvcPipe = P2PeerConPipe::ServiceFactory(kPipeCliAddr, kPipeName);
    P2PeerConDmx*  pSvcDmx  = P2PeerConDmx ::ServiceFactory(kDmxCliAddr,  kDmxService);
    if (!pSvcWsa || !pSvcPipe || !pSvcDmx) { std::printf("FATAL: a ServiceFactory failed.\n"); return 1; }
    oServer.PostP2PeerCon(pSvcWsa);
    oServer.PostP2PeerCon(pSvcPipe);
    oServer.PostP2PeerCon(pSvcDmx);
    Log("SERVER", "posted Wsa + Pipe + Dmx service cons on ONE hub/ring");

    Sleep(1000);

    MixHub oWsaCli(kWsaCliAddr, false);   oWsaCli .SetClientMessage(L"Hello via Wsa (loopback TCP)!");
    MixHub oPipeCli(kPipeCliAddr, false); oPipeCli.SetClientMessage(L"Hello via Pipe (AF_UNIX)!");
    MixHub oDmxCli(kDmxCliAddr, false);   oDmxCli .SetClientMessage(L"Hello via Dmx (in-process)!");

    oWsaCli.RequireAuth ( false );
    HANDLE hWsa  = oWsaCli .SpawnHub();
    oPipeCli.RequireAuth ( false );
    HANDLE hPipe = oPipeCli.SpawnHub();
    oDmxCli.RequireAuth ( false );
    HANDLE hDmx  = oDmxCli .SpawnHub();
    if (!hWsa || !hPipe || !hDmx) { std::printf("FATAL: a client SpawnHub failed.\n"); return 1; }

    oWsaCli .PostP2PeerCon(P2PeerConWsa ::ClientFactory(kServerAddr, L"127.0.0.1", kWsaPort));
    oPipeCli.PostP2PeerCon(P2PeerConPipe::ClientFactory(kServerAddr, kPipeName));
    oDmxCli .PostP2PeerCon(P2PeerConDmx ::ClientFactory(kServerAddr, kDmxService));
    Log("MAIN", "three clients dialing (Wsa / Pipe / Dmx)");

    Log("MAIN", "waiting up to 15s for 3 BCasts (one per transport)...");
    DWORD dwResult = WaitForSingleObject(g_hDoneEvent, 15000);

    int nExit;
    if (dwResult == WAIT_OBJECT_0)
    { Log("MAIN", "SUCCESS - server received a BCast over ALL THREE transports"); nExit = 0; }
    else
    {
        std::printf("[MAIN] TIMEOUT - only %d/%d BCasts delivered\n",
                    g_delivered.load(), kExpected);
        std::fflush(stdout);
        nExit = 3;
    }

    Log("MAIN", "shutdown begin");
    oWsaCli.CloseHub(); oPipeCli.CloseHub(); oDmxCli.CloseHub();
    oServer.CloseHub();
    WaitForSingleObject(hWsa, 3000);
    WaitForSingleObject(hPipe, 3000);
    WaitForSingleObject(hDmx, 3000);
    WaitForSingleObject(hServerThread, 3000);
    CloseHandle(hWsa); CloseHandle(hPipe); CloseHandle(hDmx); CloseHandle(hServerThread);

    CleanupP2Pmsg();
    if (g_hDoneEvent) { CloseHandle(g_hDoneEvent); g_hDoneEvent = NULL; }
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
