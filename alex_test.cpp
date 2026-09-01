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
// alex_test.cpp — portable (Linux/Windows) TWO-PROCESS loopback-TCP probe.
//
// Linux port of _TargetCore_UseExamples/AlexTest, restructured as an automatable
// two-process test. This is the LinuxPortPlan §9 Phase-3 EXIT criterion:
// "AlexTest green Linux<->Linux" in its real two-process form — a server
// process and a client process talking over the OS TCP stack, each driving
// its OWN TargetCore pump on its OWN io_uring ring in a separate address
// space (unlike wsa_mesh.cpp, which puts both hubs in one process/one ring).
//
// Modes (single executable, mode chosen by argv[1]):
//   alex_test  server [port]              -- listen on 127.0.0.1:port, wait for
//                                            the client's BCast, then exit.
//   alex_test  send   [ip] [port] [text]  -- connect, wait for login-ack, post
//                                            one BCast to the server, then exit.
//
// Verdict = process EXIT CODE (both sides):
//   0 SUCCESS   server: received the client's BCast (proves cross-process
//                       delivery over io_uring TCP)
//               client: login handshake completed + BCast posted
//   3 TIMEOUT   the awaited event did not fire within the deadline
//   1 SETUP     startup / factory failure
//
// The orchestrator (run_alex_test.sh / CTest) launches the server, then the
// client, and asserts BOTH exit 0. The server's exit 0 is the authoritative
// proof that the message crossed the process boundary.
//
// Output-formatting Win32-isms of the original (_setmode/_O_U16TEXT,
// GetLocalTime, wprintf("%s", wide)) are dropped for portability: all logging
// goes through a narrow helper (glibc treats %s as narrow).
//
// Build (Linux):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore \
//       -I../TargetCore -I../Platform -I../Platform/win-compat alex_test.cpp \
//       -L../build/TargetCore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/TargetCore -Wl,-rpath,../build/Msgcore -o alex_test

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

// --- narrow-print helpers (portable; no wide stdio) ------------------------
static std::string N(const wchar_t* w)
{
    std::string s;
    if (w) for (; *w; ++w) {
        unsigned long c = (unsigned long)*w;
        s.push_back(c < 0x80 ? (char)c : '?');
    }
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
{
    std::printf("[pid=%ld %s] %s\n", (long)GetCurrentProcessId(), role, msg);
    std::fflush(stdout);
}

// -------------------------------------------------------------------------
static const P2PaddrSTR kServerAddr = L"AlexTest.Server";
static const P2PaddrSTR kClientAddr = L"AlexTest.Client";

static HANDLE g_hDoneEvent = NULL;   // server: BCast arrived | client: BCast posted

// =========================================================================
class AlexTestHub : public P2PeerHub
{
public:
    AlexTestHub(P2PaddrSTR strAddr, bool bServer, const wchar_t* lpszMsg = NULL)
        : P2PeerHub(strAddr), m_bServer(bServer), m_bSent(false)
    { if (lpszMsg) m_strMsg = lpszMsg; }
    virtual ~AlexTestHub() {}

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
        if (!m_bServer && !m_bSent)
        {
            std::printf("[CLIENT] Login ack from '%s' - TCP connection ready.\n",
                        N(strThatP2Paddr).c_str());
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
        std::printf("[pid=%ld %s] %-16s con=%p addr='%s'\n",
                    (long)GetCurrentProcessId(),
                    m_bServer ? "SERVER" : "CLIENT",
                    lpszStage, (void*)pCon, addr.c_str());
        std::fflush(stdout);
    }

    void PrintMessage(const char* lpszKind, P2PeerMsg* pMsg)
    {
        std::string src  = pMsg ? N(pMsg->GetSource()) : std::string("<null>");
        std::string data = NBody(pMsg);
        std::printf("\n[%s] %s from '%s':\n  > %s\n\n",
                    m_bServer ? "SERVER" : "CLIENT", lpszKind, src.c_str(), data.c_str());
        std::fflush(stdout);
        // The server's success condition: it saw the client's message.
        if (m_bServer && g_hDoneEvent) SetEvent(g_hDoneEvent);
    }

    void PostTestMessage()
    {
        if (m_strMsg.IsEmpty())
            m_strMsg = L"Hello from AlexTest client (two processes)!";
        LPCWSTR   lpszMsg = m_strMsg.GetString();
        P2Psize_t nBytes  = (P2Psize_t)((m_strMsg.GetLength() + 1) * sizeof(wchar_t));
        P2PeerMsg32* pMsg = new P2PeerMsg32(
            kClientAddr, kServerAddr, P2Pmsg_BCast, lpszMsg, nBytes);
        PostP2PeerMsg(pMsg);
        std::printf("[CLIENT] Posted BCast: \"%s\"\n", N(lpszMsg).c_str());
        std::fflush(stdout);
        // The client's success condition: handshake done + message posted.
        if (g_hDoneEvent) SetEvent(g_hDoneEvent);
    }

private:
    bool    m_bServer;
    bool    m_bSent;
    CString m_strMsg;
};

// =========================================================================
static void Usage(const char* argv0)
{
    std::printf("usage:\n"
                "  %s server [port]\n"
                "  %s send   [ip] [port] [text]\n", argv0, argv0);
}

int main(int argc, char* argv[])
{
    // ---- Parse command line ----------------------------------------------
    bool        bServer = true;
    std::string strIP   = "127.0.0.1";
    short       nPort   = 7811;
    std::wstring strMsg;

    if (argc >= 2)
    {
        if (_stricmp(argv[1], "send") == 0)
        {
            bServer = false;
            if (argc >= 3) strIP = argv[2];
            if (argc >= 4) nPort = (short)atoi(argv[3]);
            if (argc >= 5) { for (const char* p = argv[4]; *p; ++p) strMsg.push_back((wchar_t)(unsigned char)*p); }
        }
        else if (_stricmp(argv[1], "server") == 0)
        {
            bServer = true;
            if (argc >= 3) nPort = (short)atoi(argv[2]);
        }
        else { Usage(argv[0]); return 1; }
    }

    std::printf("=== alex_test (two-process) — %s ===\n",
                bServer ? "SERVER" : "CLIENT");
    std::printf("Port : %d  IP : %s  pid : %ld\n\n",
                (int)nPort, bServer ? "127.0.0.1(listen)" : strIP.c_str(),
                (long)GetCurrentProcessId());
    std::fflush(stdout);

    g_hDoneEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16))
    {
        std::printf("FATAL: StartupP2Pmsg() failed.\n");
        return 1;
    }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);   // no-op shim on Linux

    P2PaddrSTR  strHubAddr = bServer ? kServerAddr : kClientAddr;
    AlexTestHub oHub(strHubAddr, bServer, (bServer || strMsg.empty()) ? NULL : strMsg.c_str());

    oHub.RequireAuth ( false );
    HANDLE hHubThread = oHub.SpawnHub();
    if (!hHubThread) { std::printf("FATAL: SpawnHub() failed.\n"); return 1; }
    Log(bServer ? "SERVER" : "CLIENT", "hub thread started");

    P2PeerConWsa* pCon = NULL;
    if (bServer)
    {
        pCon = P2PeerConWsa::ServiceFactory(kClientAddr, nPort);
        if (!pCon) { std::printf("FATAL: ServiceFactory failed.\n"); return 1; }
        oHub.PostP2PeerCon(pCon);
        Log("SERVER", "service connection posted (bind INADDR_ANY + listen)");
    }
    else
    {
        std::wstring wip(strIP.begin(), strIP.end());
        pCon = P2PeerConWsa::ClientFactory(kServerAddr, wip.c_str(), nPort);
        if (!pCon) { std::printf("FATAL: ClientFactory failed.\n"); return 1; }
        oHub.PostP2PeerCon(pCon);
        Log("CLIENT", "client connection posted (connect)");
    }

    // ---- Wait for the mode-specific success event ------------------------
    int nExit;
    if (bServer)
    {
        Log("SERVER", "waiting up to 15s for the client's BCast...");
        DWORD dw = WaitForSingleObject(g_hDoneEvent, 15000);
        if (dw == WAIT_OBJECT_0)
        { Log("SERVER", "SUCCESS - received the client's BCast over TCP"); nExit = 0; }
        else
        { Log("SERVER", "TIMEOUT - no BCast arrived"); nExit = 3; }
    }
    else
    {
        Log("CLIENT", "waiting up to 10s for login-ack + post...");
        DWORD dw = WaitForSingleObject(g_hDoneEvent, 10000);
        if (dw == WAIT_OBJECT_0)
        { Log("CLIENT", "SUCCESS - handshake completed, BCast posted"); nExit = 0; }
        else
        { Log("CLIENT", "TIMEOUT - login-ack never arrived"); nExit = 3; }
        // Give the posted BCast time to flush across the socket before teardown.
        Sleep(1500);
    }

    // ---- Shutdown --------------------------------------------------------
    Log(bServer ? "SERVER" : "CLIENT", "shutdown begin");
    oHub.CloseHub();
    WaitForSingleObject(hHubThread, 3000);
    CloseHandle(hHubThread);

    CleanupP2Pmsg();
    if (g_hDoneEvent) { CloseHandle(g_hDoneEvent); g_hDoneEvent = NULL; }
    WSACleanup();

    std::printf("Done (%s exit=%d).\n", bServer ? "SERVER" : "CLIENT", nExit);
    std::fflush(stdout);
    return nExit;
}
