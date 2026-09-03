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
// p2p_authgate.cpp — SECURITY GATE TEST for SECURITY_REVIEW finding H6.
//
//   "No authentication gate in message dispatch."
//   P2PeerTarget::On_P2PeerMsg dispatches on the first name-matching map entry
//   with no login/auth state check in the routing loop. An unauthenticated peer
//   whose message name matches any ON_P2PeerMsg(...) entry executes it with
//   full privilege.
//
// ---------------------------------------------------------------------------
// STATUS: PASSES on the current tree. H6 was fixed in commit c62613a ("Gate
// application-message dispatch behind login"), 2026-07-05 — the gate lives at
// P2PeerCon.cpp:403 (`else if ( (m_dwState & ConState_Login) )`), which drops
// the connection on an application message arriving pre-login.
//
// This test was written expecting to FAIL and did not. It is kept as the
// REGRESSION GUARD for that fix: the gate is one `else if` and nothing else in
// the tree enforces it, so it is one refactor away from silently disappearing.
//
// Passing here does NOT mean peers are authenticated. Completing a login is
// all it takes to get past this gate, and the login proves no identity —
// see p2p_authspoof.cpp, which is the one that fails.
// ---------------------------------------------------------------------------
//
// WHAT IT DOES
//
//   1. Stands up a normal P2PeerHub ("AuthGate.Server") with a normal
//      P2PeerConWsa service connection listening on loopback. Nothing about
//      the server is special or weakened — this is the same setup as
//      wsa_mesh / alex_test.
//
//   2. Opens a RAW OS SOCKET to it. Not a P2PeerCon. No P2PeerConWsa, no
//      ClientFactory, no login, no key exchange, no handshake of any kind —
//      just connect() on a bare TCP socket, exactly what an attacker with
//      netcat and a frame dump has.
//
//   3. Writes ONE well-formed TargetCore frame carrying a P2Pmsg_BCast, with
//      a source address the sender simply CLAIMS ("AuthGate.Client"). Nothing
//      has established that the sender is entitled to that address.
//
//      The frame is produced by the library's own serializer, so it is
//      byte-identical to what P2Peerio::SendP2PeerMsg puts on the wire
//      (P2Peerio.cpp:242-265):
//          pMsg->PrepareP2Piomage(GetIFmask());     // default mask = ~0
//          p = pMsg->P2Piomage();
//          n = P2Piomage_Sizeof(p);
//          Send(hFile, p, n, ...);
//      EncryptP2PiomageSwap is a passthrough while m_pP2Pcrypto == nullptr
//      (P2Peerio.cpp:1220-1221), which is the default, so no crypto step is
//      skipped here — there is none to skip.
//
//   4. Asserts the hub's On_P2PeerBCast handler DOES NOT FIRE.
//
// VERDICT = process EXIT CODE:
//   0  PASS   the handler did not fire — an auth gate is present and working
//   1  FAIL   the handler FIRED for an unauthenticated peer  => H6 CONFIRMED
//   2  SETUP  startup / socket / factory failure (test inconclusive)
//
// A note on what a PASS must mean. Exit 0 is only meaningful if the positive
// path still works — a hub that dispatches nothing would also "pass" here.
// wsa_mesh and alex_test are the positive controls: they must stay green
// alongside this test. Run all three.
//
// Build (Linux):
//   g++ -std=c++23 -fpermissive -D_UNICODE -DUNICODE -I. -I../Msgcore \
//       -I../TargetCore -I../Msgcore/Platform -I../Msgcore/Platform/win-compat p2p_authgate.cpp \
//       -L../build/TargetCore -ltargetcore -L../build/Msgcore -lmsgcore -luring \
//       -Wl,-rpath,../build/TargetCore -Wl,-rpath,../build/Msgcore -o p2p_authgate

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>
#include <string>

#ifdef _WIN32
#  define CLOSESOCK  closesocket
#else
#  include <unistd.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  define CLOSESOCK  closesocket
#endif
//  Deliberately the platform's SOCKET on BOTH sides. Off Windows that is the
//  shim's type (Platform/p2psock.h), and `socket()` there is a MACRO returning
//  it - so declaring our own `int` and assigning the result stuffs a pointer
//  into an int, which -fpermissive downgrades to a warning and which then makes
//  every later bind/connect operate on garbage. "Raw" here means raw with
//  respect to P2PeerCon and the login protocol, which is what these tests are
//  about; it was never meant to mean bypassing the platform socket layer.
typedef SOCKET RawSock;

// ---------------------------------------------------------------------------
static const P2PaddrSTR kServerAddr = L"AuthGate.Server";
static const P2PaddrSTR kClientAddr = L"AuthGate.Client";   // claimed, never proven

static HANDLE g_hHandlerFired = NULL;   // set iff a handler ran for the raw peer
static bool   g_bLoginSeen    = false;  // did the server think anyone logged in?

static void Log(const char* msg)
{
    std::printf("[authgate] %s\n", msg);
    std::fflush(stdout);
}

static std::string N(const wchar_t* w)
{
    std::string s;
    if (w) for (; *w; ++w) {
        unsigned long c = (unsigned long)*w;
        s.push_back(c < 0x80 ? (char)c : '?');
    }
    return s;
}

// =========================================================================
// A perfectly ordinary hub. No weakening, no special casing — the point is
// that a stock hub with a stock handler map is reachable pre-auth.
class AuthGateHub : public P2PeerHub
{
public:
    explicit AuthGateHub(P2PaddrSTR strAddr) : P2PeerHub(strAddr) {}
    virtual ~AuthGateHub() {}

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        Breach("On_P2PeerBCast", pMsg);
        return msgHANDLED;
    }

    virtual msgRESULT On_P2PeerUCast(P2PeerMsg* pMsg) override
    {
        Breach("On_P2PeerUCast", pMsg);
        return msgHANDLED;
    }

    // Recorded so the report can distinguish "no gate" from "the peer somehow
    // completed a login". If this fires, the test result needs a human.
    virtual conRESULT On_ConLogin(P2PeerCon* pCon, P2PaddrSTR strThatP2Paddr,
                                  const void* pvLoginMsg, P2Psize_t iSize) override
    {
        g_bLoginSeen = true;
        std::printf("[authgate] NOTE: On_ConLogin fired for '%s'\n",
                    N(strThatP2Paddr).c_str());
        std::fflush(stdout);
        return P2PeerHub::On_ConLogin(pCon, strThatP2Paddr, pvLoginMsg, iSize);
    }

private:
    void Breach(const char* lpszHandler, P2PeerMsg* pMsg)
    {
        std::string src = pMsg ? N(pMsg->GetSource()) : std::string("<null>");
        std::printf("\n"
                    "  *** HANDLER REACHED BY AN UNAUTHENTICATED PEER ***\n"
                    "      handler : %s\n"
                    "      claimed source : '%s'\n"
                    "      login completed for this peer : %s\n"
                    "\n",
                    lpszHandler, src.c_str(), g_bLoginSeen ? "yes" : "NO");
        std::fflush(stdout);
        if (g_hHandlerFired) SetEvent(g_hHandlerFired);
    }
};

// =========================================================================
// The attacker: a bare TCP socket, no P2PeerCon anywhere in sight.
static bool RawConnectAndSend(short nPort, int* pnSetupErr)
{
    *pnSetupErr = 0;

    // ---- 1. Build the frame with the library's own serializer -------------
    // Identical to P2Peerio::SendP2PeerMsg (P2Peerio.cpp:242-263).
    static const wchar_t* kPayload = L"unauthenticated";
    P2Psize_t nBytes = (P2Psize_t)((wcslen(kPayload) + 1) * sizeof(wchar_t));

    P2PeerMsg32 oMsg(kClientAddr, kServerAddr, P2Pmsg_BCast, kPayload, nBytes);
    oMsg.PrepareP2Piomage(~(DWORD)0);          // P2Peerio's default m_dwIFmask
    const P2Piomage* pImage = oMsg.P2Piomage();
    if (!pImage) { Log("SETUP: P2Piomage() returned null"); *pnSetupErr = 2; return false; }

    UINT nImage = P2Piomage_Sizeof(pImage);
    if (!nImage) { Log("SETUP: P2Piomage_Sizeof() == 0"); *pnSetupErr = 2; return false; }

    std::printf("[authgate] frame built by the library: %u bytes\n", nImage);
    std::fflush(stdout);

    // ---- 2. Raw socket ----------------------------------------------------
    RawSock s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { Log("SETUP: socket() failed"); *pnSetupErr = 2; return false; }

    sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)nPort);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");

    // The listener may not be bound yet; the hub posts it asynchronously.
    bool bConnected = false;
    for (int i = 0; i < 40 && !bConnected; ++i)          // up to ~4s
    {
        if (connect(s, (sockaddr*)&sa, sizeof(sa)) != SOCKET_ERROR) { bConnected = true; break; }
        Sleep(100);
    }
    if (!bConnected)
    {
        Log("SETUP: connect() to the hub never succeeded");
        CLOSESOCK(s);
        *pnSetupErr = 2;
        return false;
    }
    Log("raw TCP socket connected — NO login, NO key exchange, NO handshake");

    // ---- 3. Write the frame and nothing else ------------------------------
    const char* p    = (const char*)pImage;
    UINT        left = nImage;
    while (left > 0)
    {
        int n = send(s, p, (int)left, 0);
        if (n <= 0) { Log("SETUP: send() failed mid-frame"); CLOSESOCK(s); *pnSetupErr = 2; return false; }
        p    += n;
        left -= (UINT)n;
    }
    Log("frame written to the socket");

    // Hold the connection open so the server does not tear it down before the
    // pump has had a chance to dispatch.
    Sleep(3000);
    CLOSESOCK(s);
    return true;
}

// =========================================================================
int main(int argc, char* argv[])
{
    short nPort = (argc >= 2) ? (short)atoi(argv[1]) : 7813;

    std::printf("=== p2p_authgate — SECURITY_REVIEW H6 gate test ===\n");
    std::printf("Port : %d\n", (int)nPort);
    std::printf("Asserting: an unauthenticated peer must NOT reach a handler.\n\n");
    std::fflush(stdout);

    g_hHandlerFired = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16)) { Log("SETUP: StartupP2Pmsg() failed"); return 2; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);          // no-op shim on Linux

    int nExit = 2;
    {
        AuthGateHub oHub(kServerAddr);

        //  RequireAuth(false), deliberately, and it makes the claim STRONGER.
        //  Since ProductionPlan.md Stage 3 step 8 auth is required by default, and
        //  an armed hub with keys would refuse this raw socket at the key agreement
        //  - which would make the test pass for a reason that has nothing to do
        //  with H6. The gate under test keys on ConState_Login and NOT on
        //  RequireAuth (P2PeerCon.cpp, `else if ( (m_dwState & ConState_Login) )`),
        //  so turning auth off is what leaves the dispatch gate as the only thing
        //  standing between the attacker and the handler. It also keeps the setup
        //  identical to wsa_mesh / alex_test, which is what the header claims.
        oHub.RequireAuth ( false );
        HANDLE hHubThread = oHub.SpawnHub();
        if (!hHubThread) { Log("SETUP: SpawnHub() failed"); return 2; }
        Log("hub thread started");

        P2PeerConWsa* pCon = P2PeerConWsa::ServiceFactory(kClientAddr, nPort);
        if (!pCon) { Log("SETUP: ServiceFactory failed"); return 2; }
        oHub.PostP2PeerCon(pCon);
        Log("service connection posted (bind + listen)");

        int nSetupErr = 0;
        if (RawConnectAndSend(nPort, &nSetupErr))
        {
            // Give the pump every chance to dispatch. We WANT it to have had
            // time — a timeout here must mean "refused", not "too slow".
            DWORD dw = WaitForSingleObject(g_hHandlerFired, 5000);
            if (dw == WAIT_OBJECT_0)
            {
                std::printf(
                  "RESULT: FAIL — H6 CONFIRMED.\n"
                  "  A handler executed for a peer that never authenticated.\n"
                  "  Any peer able to complete a TCP connection can invoke any\n"
                  "  handler registered with ON_P2PeerMsg(...).\n"
                  "  See Ahtung_Disaster.md and SECURITY.md (Track B, step 1).\n");
                nExit = 1;
            }
            else
            {
                std::printf(
                  "RESULT: PASS — the unauthenticated frame did not reach a handler.\n"
                  "  NOTE: this is only meaningful if wsa_mesh and alex_test are\n"
                  "  also green. Confirm the positive path still works.\n");
                nExit = 0;
            }
        }
        else
        {
            std::printf("RESULT: INCONCLUSIVE — test setup failed, see above.\n");
            nExit = nSetupErr ? nSetupErr : 2;
        }

        Log("shutdown begin");
        oHub.CloseHub();
        WaitForSingleObject(hHubThread, 3000);
        CloseHandle(hHubThread);
    }

    CleanupP2Pmsg();
    if (g_hHandlerFired) { CloseHandle(g_hHandlerFired); g_hHandlerFired = NULL; }
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
