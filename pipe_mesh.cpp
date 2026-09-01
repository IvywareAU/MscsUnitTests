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
// pipe_mesh.cpp — portable (Linux/Windows) single-process two-hub named-pipe probe.
//
// Linux port of _TargetCore_UseExamples/PipeMeshTest: exercises the FULL TargetCore pump
// lifecycle (SpawnHub -> pump thread -> CreateIoCompletionPort / GetQueuedCompletionStatus
// loop -> PostQueuedCompletionStatus delivery) plus the login handshake, over the
// P2PeerConPipe transport. On Windows this is a real NT named pipe; on Linux the shim
// maps \\.\pipe\Name to an AF_UNIX SOCK_STREAM socket at $XDG_RUNTIME_DIR/p2pmsg/Name.sock
// (server: CreateNamedPipe = socket/bind/listen, ConnectNamedPipe = io_uring accept that
// morphs the handle; client: CreateFile = socket+connect — the runtime item this increment
// closes). See LinuxPortPlan §6.2, §9 Phase 4.
//
// The output-formatting Win32-isms of the original (_setmode/_O_U16TEXT, _CrtSetReportHook,
// GetLocalTime, wprintf("%s", wide)) are dropped for portability: all logging goes through
// a narrow helper so it behaves identically on glibc (%s is narrow there).
//
// Verdict = process EXIT CODE:  0 SUCCESS | 3 TIMEOUT | 1 SETUP.
//
// Build (Linux):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore -I../TargetCore \
//       -I../Platform -I../Platform/win-compat pipe_mesh.cpp \
//       -L../build/TargetCore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/TargetCore -Wl,-rpath,../build/Msgcore -o pipe_mesh

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConPipe.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
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
    std::printf("[%s] %s\n", role, msg);
    std::fflush(stdout);
}

// -------------------------------------------------------------------------
static LPCTSTR          kPipeName    = _T("\\\\.\\pipe\\P2PmeshProbe");
static const P2PaddrSTR kServerAddr  = L"PipeMesh.Server";
static const P2PaddrSTR kClientAddr  = L"PipeMesh.Client";

static HANDLE g_hDoneEvent = NULL;

// =========================================================================
class PipeMeshHub : public P2PeerHub
{
public:
    PipeMeshHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr), m_bServer(bServer), m_bSent(false) {}
    virtual ~PipeMeshHub() {}

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
            std::printf("[CLIENT] Login ack from '%s' - pipe connection ready.\n",
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
        std::printf("[%s] %-16s con=%p addr='%s'\n",
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
        if (m_bServer && g_hDoneEvent) SetEvent(g_hDoneEvent);
    }

    void PostTestMessage()
    {
        LPCWSTR   lpszMsg = L"Hello over a named pipe, in one process!";
        P2Psize_t nBytes  = (P2Psize_t)((wcslen(lpszMsg) + 1) * sizeof(wchar_t));
        P2PeerMsg32* pMsg = new P2PeerMsg32(
            kClientAddr, kServerAddr, P2Pmsg_BCast, lpszMsg, nBytes);
        PostP2PeerMsg(pMsg);
        std::printf("[CLIENT] Posted BCast: \"%s\"\n", N(lpszMsg).c_str());
        std::fflush(stdout);
    }

private:
    bool m_bServer;
    bool m_bSent;
};

// =========================================================================
int main(int /*argc*/, char* /*argv*/[])
{
    std::printf("=== pipe_mesh - single-process two-hub NAMED PIPE probe ===\n");
    std::printf("Pipe : %s\n\n", N(kPipeName).c_str());
    std::fflush(stdout);

    g_hDoneEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16))
    {
        std::printf("FATAL: StartupP2Pmsg() failed.\n");
        return 1;
    }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);   // no-op shim on Linux

    // ---- Hub A: SERVER (creates + listens on the named pipe) --------------
    PipeMeshHub oServer(kServerAddr, /*bServer*/ true);
    oServer.RequireAuth ( false );
    HANDLE hServerThread = oServer.SpawnHub();
    if (!hServerThread) { std::printf("FATAL: server SpawnHub failed.\n"); return 1; }
    Log("SERVER", "hub thread started");

    P2PeerConPipe* pSvcCon = P2PeerConPipe::ServiceFactory(kClientAddr, kPipeName);
    if (!pSvcCon) { std::printf("FATAL: ServiceFactory failed.\n"); return 1; }
    oServer.PostP2PeerCon(pSvcCon);
    Log("SERVER", "service pipe connection posted (CreateNamedPipe + ConnectNamedPipe)");

    // Let the server pump create the pipe + post its overlapped accept before the
    // client's CreateFile(OPEN_EXISTING) dials in.
    Sleep(750);

    // ---- Hub B: CLIENT (opens the existing named pipe) --------------------
    PipeMeshHub oClient(kClientAddr, /*bServer*/ false);
    oClient.RequireAuth ( false );
    HANDLE hClientThread = oClient.SpawnHub();
    if (!hClientThread) { std::printf("FATAL: client SpawnHub failed.\n"); return 1; }
    Log("CLIENT", "hub thread started");

    P2PeerConPipe* pCliCon = P2PeerConPipe::ClientFactory(kServerAddr, kPipeName);
    if (!pCliCon) { std::printf("FATAL: ClientFactory failed.\n"); return 1; }
    oClient.PostP2PeerCon(pCliCon);
    Log("CLIENT", "client pipe connection posted (CreateFile OPEN_EXISTING)");

    // ---- Wait for the round trip -----------------------------------------
    Log("MAIN", "waiting up to 10s for login-ack + BCast delivery...");
    DWORD dwResult = WaitForSingleObject(g_hDoneEvent, 10000);

    int nExit;
    if (dwResult == WAIT_OBJECT_0)
    {
        Log("MAIN", "SUCCESS - server received the client's BCast over the pipe");
        nExit = 0;
    }
    else
    {
        Log("MAIN", "TIMEOUT - no BCast delivered (handshake did not complete)");
        nExit = 3;
    }

    // ---- Shutdown --------------------------------------------------------
    Log("MAIN", "shutdown begin");
    oClient.CloseHub();
    oServer.CloseHub();
    WaitForSingleObject(hClientThread, 3000);
    WaitForSingleObject(hServerThread, 3000);
    CloseHandle(hClientThread);
    CloseHandle(hServerThread);

    CleanupP2Pmsg();
    if (g_hDoneEvent) { CloseHandle(g_hDoneEvent); g_hDoneEvent = NULL; }
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
