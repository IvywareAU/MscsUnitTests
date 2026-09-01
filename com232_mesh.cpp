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
// com232_mesh.cpp — portable (Linux/Windows) single-process two-hub serial probe.
//
// Linux port of _TargetCore_UseExamples/Com232MeshTest: exercises the FULL TargetCore pump
// lifecycle (SpawnHub -> pump thread -> CreateIoCompletionPort / GetQueuedCompletionStatus
// loop -> WaitCommEvent(EV_RXCHAR)=io_uring poll -> PostQueuedCompletionStatus) plus the
// login handshake, over the P2PeerCon232 RS-232 transport (termios on Linux, DCB on Win).
//
// A serial link is a physical null-modem. On Windows the original needs a com0com COM5<->
// COM6 pair. On Linux this harness builds an equivalent VIRTUAL null-modem entirely in
// process, needing no root, no socat, no hardware:
//   * two PTY master/slave pairs (posix_openpt): masterA/slaveA, masterB/slaveB
//   * the P2P_COM<n> env override (Platform §6.2 configurable COM map) points
//     COM5 -> slaveA, COM6 -> slaveB
//   * a relay thread shuttles bytes masterA<->masterB, cross-connecting the two slaves
//   * server opens COM5 (slaveA) and arms its WaitCommEvent poll; client opens COM6
//     (slaveB) and drives the login handshake; bytes flow slaveB->masterB->masterA->slaveA
//     (and back), exactly like a null-modem cable.
//
// Verdict = process EXIT CODE:  0 SUCCESS | 3 TIMEOUT | 1 SETUP.
//
// Build (Linux):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore -I../TargetCore \
//       -I../Platform -I../Platform/win-compat com232_mesh.cpp \
//       -L../build/TargetCore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/TargetCore -Wl,-rpath,../build/Msgcore -o com232_mesh

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerCon232.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>
#include <string>

#ifndef _WIN32
  #include <cstdlib>       // posix_openpt/grantpt/unlockpt/ptsname/setenv
  #include <fcntl.h>
  #include <unistd.h>
  #include <termios.h>
  #include <poll.h>
  #include <atomic>
  #include <thread>
#endif

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
static const short      kServerComPort = 5;  // server listens on COM5
static const short      kClientComPort = 6;  // client dials from COM6
static const P2PaddrSTR kServerAddr    = L"Com232Mesh.Server";
static const P2PaddrSTR kClientAddr    = L"Com232Mesh.Client";

static HANDLE g_hDoneEvent = NULL;

// =========================================================================
//  Virtual null-modem (Linux only): two PTY pairs + a byte-relay thread.
// =========================================================================
#ifndef _WIN32
namespace {
    int              g_masterA = -1, g_masterB = -1;
    std::atomic<bool> g_relayStop{false};
    std::thread      g_relay;

    // open a PTY master, unlock it, and make it raw (no echo/CR-NL fixups that would
    // corrupt the binary TargetCore framing); return master fd, fill slave path.
    int OpenPtyMaster(std::string& slavePath)
    {
        int m = ::posix_openpt(O_RDWR | O_NOCTTY);
        if (m < 0) return -1;
        if (::grantpt(m) != 0 || ::unlockpt(m) != 0) { ::close(m); return -1; }
        const char* sn = ::ptsname(m);
        if (!sn) { ::close(m); return -1; }
        slavePath = sn;
        termios tio{};
        if (::tcgetattr(m, &tio) == 0) { ::cfmakeraw(&tio); ::tcsetattr(m, TCSANOW, &tio); }
        return m;
    }

    // shuttle bytes both directions between the two masters, cross-connecting the slaves.
    void RelayLoop()
    {
        char buf[4096];
        pollfd fds[2] = { { g_masterA, POLLIN, 0 }, { g_masterB, POLLIN, 0 } };
        while (!g_relayStop.load(std::memory_order_relaxed)) {
            fds[0].revents = fds[1].revents = 0;
            int r = ::poll(fds, 2, 200);
            if (r <= 0) continue;
            if (fds[0].revents & POLLIN) {
                ssize_t n = ::read(g_masterA, buf, sizeof buf);
                if (n > 0) { ssize_t off = 0; while (off < n) { ssize_t w = ::write(g_masterB, buf + off, n - off); if (w <= 0) break; off += w; } }
            }
            if (fds[1].revents & POLLIN) {
                ssize_t n = ::read(g_masterB, buf, sizeof buf);
                if (n > 0) { ssize_t off = 0; while (off < n) { ssize_t w = ::write(g_masterA, buf + off, n - off); if (w <= 0) break; off += w; } }
            }
        }
    }

    // returns false on failure (SETUP verdict)
    bool StartNullModem()
    {
        std::string slaveA, slaveB;
        g_masterA = OpenPtyMaster(slaveA);
        g_masterB = OpenPtyMaster(slaveB);
        if (g_masterA < 0 || g_masterB < 0) return false;
        ::setenv("P2P_COM5", slaveA.c_str(), 1);
        ::setenv("P2P_COM6", slaveB.c_str(), 1);
        std::printf("[MAIN] virtual null-modem: COM5=%s <-> COM6=%s\n",
                    slaveA.c_str(), slaveB.c_str());
        std::fflush(stdout);
        g_relay = std::thread(RelayLoop);
        return true;
    }

    void StopNullModem()
    {
        g_relayStop.store(true, std::memory_order_relaxed);
        if (g_relay.joinable()) g_relay.join();
        if (g_masterA >= 0) ::close(g_masterA);
        if (g_masterB >= 0) ::close(g_masterB);
    }
}
#endif // !_WIN32

// =========================================================================
class Com232MeshHub : public P2PeerHub
{
public:
    Com232MeshHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr), m_bServer(bServer), m_bSent(false) {}
    virtual ~Com232MeshHub() {}

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
            std::printf("[CLIENT] Login ack from '%s' - serial connection ready.\n",
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
        LPCWSTR   lpszMsg = L"Hello over an RS-232 serial connection!";
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
    std::printf("=== com232_mesh - single-process two-hub serial probe ===\n");
    std::printf("Ports : server COM%d <-> client COM%d\n\n",
                (int)kServerComPort, (int)kClientComPort);
    std::fflush(stdout);

#ifndef _WIN32
    if (!StartNullModem())
    {
        std::printf("FATAL: could not create the PTY null-modem.\n");
        return 1;
    }
#endif

    g_hDoneEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16))
    {
        std::printf("FATAL: StartupP2Pmsg() failed.\n");
        return 1;
    }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);   // no-op shim on Linux

    // ---- Hub A: SERVER (listens on COM5) ----------------------------------
    Com232MeshHub oServer(kServerAddr, /*bServer*/ true);
    oServer.RequireAuth ( false );
    HANDLE hServerThread = oServer.SpawnHub();
    if (!hServerThread) { std::printf("FATAL: server SpawnHub failed.\n"); return 1; }
    Log("SERVER", "hub thread started");

    P2PeerCon232* pSvcCon = P2PeerCon232::ServiceFactory(kClientAddr, kServerComPort);
    if (!pSvcCon) { std::printf("FATAL: ServiceFactory failed.\n"); return 1; }
    oServer.PostP2PeerCon(pSvcCon);
    Log("SERVER", "service serial connection posted");

    // Let the server pump run Listen()/Accept() so WaitCommEvent(EV_RXCHAR) is armed
    // BEFORE the client's login bytes hit the wire.
    Sleep(750);

    // ---- Hub B: CLIENT (dials from COM6) ----------------------------------
    Com232MeshHub oClient(kClientAddr, /*bServer*/ false);
    oClient.RequireAuth ( false );
    HANDLE hClientThread = oClient.SpawnHub();
    if (!hClientThread) { std::printf("FATAL: client SpawnHub failed.\n"); return 1; }
    Log("CLIENT", "hub thread started");

    P2PeerCon232* pCliCon = P2PeerCon232::ClientFactory(kServerAddr, kClientComPort);
    if (!pCliCon) { std::printf("FATAL: ClientFactory failed.\n"); return 1; }
    oClient.PostP2PeerCon(pCliCon);
    Log("CLIENT", "client serial connection posted");

    // ---- Wait for the round trip -----------------------------------------
    Log("MAIN", "waiting up to 15s for login-ack + BCast delivery...");
    DWORD dwResult = WaitForSingleObject(g_hDoneEvent, 15000);

    int nExit;
    if (dwResult == WAIT_OBJECT_0)
    {
        Log("MAIN", "SUCCESS - server received the client's BCast over RS-232");
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

#ifndef _WIN32
    StopNullModem();
#endif

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
