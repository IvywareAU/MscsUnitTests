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
// p2p_authrelay.cpp — SECURITY GATE TEST: is the proven identity bound to the
// CHANNEL it was proven on, or only to the login message?
//
// BACKGROUND — the fourth gate.
//
//   p2p_authgate   : an unauthenticated peer cannot reach a handler.      PASSES
//   p2p_authspoof  : a logged-in peer cannot forge its source mid-session. PASSES
//   p2p_authpsk    : a peer cannot claim an identity that is not its own.  PASSES
//   p2p_authrelay  : an identity proven on one channel cannot be borrowed
//                    by another party on that same channel.               <-- this one
//
//   The signed login (P2PAuthLogin.h) proves WHO connected. It signs the
//   addresses, a nonce and a timestamp — and nothing about the transport the
//   login travelled over, because there is nothing to sign: the wire is
//   cleartext and there is no key exchange on the live path.
//
//   So the proof is attached to a MESSAGE, not to a CONNECTION. Anyone sitting
//   between two peers can forward that message untouched and inherit the trust
//   it establishes. The signature still verifies — it is genuine, it was made
//   by the real client, over exactly the addresses the server expects — and
//   from that moment the server treats everything arriving on that socket as
//   coming from the authenticated peer.
//
//   Note carefully what the attacker does NOT need. No key. No forged
//   signature. No weakness in ECDSA, in the nonce cache or in the freshness
//   window: the login it relays is FRESH, its nonce is UNSEEN, and it is
//   replayed nowhere — it is delivered exactly once, to exactly the server it
//   was addressed to. Every existing check is satisfied because none of them
//   is asking the question this test asks.
//
// ---------------------------------------------------------------------------
// THIS TEST WAS EXPECTED TO FAIL, AND NOW PASSES (measured 2026-08-14).
// It encodes the REQUIREMENT ("authentication must bind to the channel"), not
// the current behaviour, which is why it survives its own fix. It went green
// when BOTH halves landed: P2PAuthLogin.h computes a 32-byte SHA-256 channel
// binding (AuthChannelBind / kAuthBindLen) and folds it into the SIGNED
// TRANSCRIPT. The second half is the part easy to leave out, and this test is
// what would notice if it were ever dropped again.
// Do not "fix" it by relaxing the assertion.
// ---------------------------------------------------------------------------
//
// WHAT IT DOES — one server, one honest client, one machine in the middle.
//
//   The middle is a plain TCP relay: it listens, accepts the client, dials the
//   server, and copies bytes both ways without modifying any of them. It never
//   parses the handshake and never needs to.
//
//   Phase 1 (POSITIVE CONTROL): the honest client — holding the key the
//   server's allow-list names for it, with RequireAuth(true) at both ends —
//   connects THROUGH the relay, logs in, and posts a message. This MUST
//   arrive. It proves the relay is transparent and the authenticated session
//   is real; without it, phase 2 would prove nothing.
//
//   Phase 2 (THE PROBE): the relay writes ONE frame of its own onto the
//   server-bound socket, sourced as 'Relay.Client'. The honest client never
//   sent it and never will. This MUST NOT be dispatched.
//
//   The injected frame is produced by the library's own serializer, exactly as
//   p2p_authgate does, so it is byte-identical to what P2Peerio would put on
//   the wire. Today that is trivially possible because the wire is plaintext;
//   once a session key exists, the equivalent attack is to complete the key
//   exchange with the server under the relay's OWN key while forwarding the
//   client's login — which is precisely what binding the login signature to
//   the exchange transcript prevents.
//
// VERDICT = process EXIT CODE:
//   0  PASS   the injected frame was not dispatched — auth is channel-bound
//   1  FAIL   it WAS dispatched => a relay can borrow an authenticated identity
//   2  SETUP  startup / socket / factory failure (test inconclusive)
//   3  INCONCLUSIVE phase 1 never arrived — the relay or transport is broken
//
// Build (Linux): as p2p_authgate.cpp.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"
#include "P2PIdentityStore.h"
#include "P2PAuthLogin.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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
static const P2PaddrSTR kServerAddr = L"Relay.Server";
static const P2PaddrSTR kClientAddr = L"Relay.Client";
static const P2PaddrSTR kDomain     = L"Relay.*";

static const wchar_t kHonestPayload  [] = L"honest";
static const wchar_t kInjectedPayload[] = L"INJECTED-BY-THE-RELAY";

static HANDLE g_hHonest   = NULL;      // phase 1 landed
static HANDLE g_hInjected = NULL;      // phase 2 landed (it must not)
static HANDLE g_hRelayUp  = NULL;      // the relay has both sockets

// The relay's socket to the SERVER. The injected frame goes out on this one,
// which is the whole point: it is the same TCP connection the honest client's
// login authenticated.
static RawSock           g_sToServer = INVALID_SOCKET;
static CRITICAL_SECTION g_csToServer;
static volatile bool    g_bRelayStop = false;

static void Log(const char* msg)
{
    std::printf("[authrelay] %s\n", msg);
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

// ---------------------------------------------------------------------------
// Identity provisioning — as p2p_authpsk. Private keys stay put; only public
// points are published.
// ---------------------------------------------------------------------------
static std::vector<std::string> g_vTempFiles;

static std::string TempPath(const char* pszLeaf)
{
    char szDir[MAX_PATH + 2] = { 0 };
    DWORD n = GetTempPathA(MAX_PATH + 1, szDir);
    std::string s = (n > 0 && n <= MAX_PATH) ? std::string(szDir) : std::string(".\\");
    char szPid[32];
    std::snprintf(szPid, sizeof(szPid), "%lu", (unsigned long)GetCurrentProcessId());
    s += "p2p_authrelay_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
    DeleteFileA(s.c_str());
    g_vTempFiles.push_back(s);
    return s;
}

static void ScrubTempFiles()
{
    for (size_t i = 0; i < g_vTempFiles.size(); ++i)
        DeleteFileA(g_vTempFiles[i].c_str());
    g_vTempFiles.clear();
}

static bool MakeIdentity(const std::string& sPath, unsigned char* pPubOut)
{
    p2pcng::EcdsaP256 oKey;
    if (!oKey.Generate())                                          return false;
    if (p2pcng::SaveIdentity(sPath.c_str(), oKey) != p2pcng::IdOk)  return false;
    return oKey.ExportPublic(pPubOut);
}

// =========================================================================
class RelayHub : public P2PeerHub
{
public:
    RelayHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr), m_bServer(bServer), m_bSent(false)
    { m_strSelf = strAddr; }
    virtual ~RelayHub() {}

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        if (m_bServer && pMsg)
        {
            std::string src = N(pMsg->GetSource());

            // Both messages claim the same (genuinely authenticated) source,
            // so the payload is what tells them apart. That is the finding in
            // one sentence: the source is not in question, the SENDER is.
            //  COPIED OUT, not cast in place: Data() addresses bytes inside
            //  the pack(1) message image and guarantees them no alignment,
            //  so assigning through a (const wchar_t*) is undefined - F-S5-3.
            std::wstring body;
            if (pMsg->DataSize() > 0 && pMsg->Data())
            {
                body.resize((size_t)pMsg->DataSize() / sizeof(wchar_t));
                if (!body.empty())
                    std::memcpy(&body[0], pMsg->Data(),
                                body.size() * sizeof(wchar_t));
            }
            while (!body.empty() && body.back() == L'\0') body.pop_back();

            std::printf("[authrelay] SERVER handler ran; source='%s' payload='%s'\n",
                        src.c_str(), N(body.c_str()).c_str());
            std::fflush(stdout);

            if      (body == kInjectedPayload) { if (g_hInjected) SetEvent(g_hInjected); }
            else if (body == kHonestPayload)   { if (g_hHonest)   SetEvent(g_hHonest);   }
        }
        return msgHANDLED;
    }

    virtual conRESULT On_ConLogin(P2PeerCon* pCon, P2PaddrSTR strThatP2Paddr,
                                  const void* pvLoginMsg, P2Psize_t iSize) override
    {
        if (m_bServer)
        {
            std::printf("[authrelay] SERVER accepted a PROVEN login as '%s'"
                        " (payload %d bytes)\n",
                        N(strThatP2Paddr).c_str(), (int)iSize);
            std::fflush(stdout);
        }
        return P2PeerHub::On_ConLogin(pCon, strThatP2Paddr, pvLoginMsg, iSize);
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
            P2Psize_t nBytes = (P2Psize_t)sizeof(kHonestPayload);
            PostP2PeerMsg(new P2PeerMsg32(m_strSelf.GetString(), kServerAddr,
                                          P2Pmsg_BCast, kHonestPayload, nBytes));
            Log("honest client logged in (mutually proven) and posted");
        }
        return result;
    }

private:
    bool    m_bServer;
    bool    m_bSent;
    CString m_strSelf;
};

// =========================================================================
// The machine in the middle. It copies bytes. It does not parse them, does not
// modify them, and holds no key of any kind.
struct RelayPorts { short nListen; short nServer; };
static RelayPorts g_oPorts = { 0, 0 };
static RawSock     g_sFromClient = INVALID_SOCKET;
static RawSock     g_sListen     = INVALID_SOCKET;

static bool SendAll(RawSock s, const char* p, int n)
{
    while (n > 0)
    {
        int w = send(s, p, n, 0);
        if (w <= 0) return false;
        p += w; n -= w;
    }
    return true;
}

// server -> client
static DWORD WINAPI RelayS2C(void*)
{
    char buf[8192];
    while (!g_bRelayStop)
    {
        int n = recv(g_sToServer, buf, (int)sizeof(buf), 0);
        if (n <= 0) break;
        if (!SendAll(g_sFromClient, buf, n)) break;
    }
    return 0;
}

// client -> server
static DWORD WINAPI RelayC2S(void*)
{
    char buf[8192];
    while (!g_bRelayStop)
    {
        int n = recv(g_sFromClient, buf, (int)sizeof(buf), 0);
        if (n <= 0) break;
        EnterCriticalSection(&g_csToServer);
        bool ok = SendAll(g_sToServer, buf, n);
        LeaveCriticalSection(&g_csToServer);
        if (!ok) break;
    }
    return 0;
}

static DWORD WINAPI RelayAccept(void*)
{
    g_sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_sListen == INVALID_SOCKET) { Log("SETUP: relay socket() failed"); return 1; }

    int nOne = 1;
    setsockopt(g_sListen, SOL_SOCKET, SO_REUSEADDR, (const char*)&nOne, sizeof(nOne));

    sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((unsigned short)g_oPorts.nListen);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(g_sListen, (sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR ||
        listen(g_sListen, 4) == SOCKET_ERROR)
    { Log("SETUP: relay bind/listen failed"); return 1; }

    Log("relay listening — it will copy bytes and modify none of them");

    g_sFromClient = accept(g_sListen, nullptr, nullptr);
    if (g_sFromClient == INVALID_SOCKET) { Log("SETUP: relay accept() failed"); return 1; }

    RawSock sOut = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sOut == INVALID_SOCKET) { Log("SETUP: relay upstream socket() failed"); return 1; }
    sockaddr_in sb;
    std::memset(&sb, 0, sizeof(sb));
    sb.sin_family      = AF_INET;
    sb.sin_port        = htons((unsigned short)g_oPorts.nServer);
    sb.sin_addr.s_addr = inet_addr("127.0.0.1");

    bool bUp = false;
    for (int i = 0; i < 40 && !bUp; ++i)
    {
        if (connect(sOut, (sockaddr*)&sb, sizeof(sb)) != SOCKET_ERROR) { bUp = true; break; }
        Sleep(100);
    }
    if (!bUp) { Log("SETUP: relay could not reach the server"); CLOSESOCK(sOut); return 1; }

    g_sToServer = sOut;
    Log("relay connected to the server — the client's session now runs through it");
    if (g_hRelayUp) SetEvent(g_hRelayUp);

    HANDLE h1 = CreateThread(NULL, 0, RelayC2S, NULL, 0, NULL);
    HANDLE h2 = CreateThread(NULL, 0, RelayS2C, NULL, 0, NULL);
    if (h1) { WaitForSingleObject(h1, INFINITE); CloseHandle(h1); }
    if (h2) { WaitForSingleObject(h2, 1000);     CloseHandle(h2); }
    return 0;
}

// The probe: one frame, written by the relay onto the authenticated socket.
static bool InjectAsClient()
{
    P2Psize_t nBytes = (P2Psize_t)sizeof(kInjectedPayload);
    P2PeerMsg32 oMsg(kClientAddr, kServerAddr, P2Pmsg_BCast, kInjectedPayload, nBytes);
    oMsg.PrepareP2Piomage(~(DWORD)0);           // P2Peerio's default m_dwIFmask
    const P2Piomage* pImage = oMsg.P2Piomage();
    if (!pImage) { Log("SETUP: P2Piomage() returned null"); return false; }
    UINT nImage = P2Piomage_Sizeof(pImage);
    if (!nImage) { Log("SETUP: P2Piomage_Sizeof() == 0"); return false; }

    std::printf("[authrelay] relay injecting %u bytes sourced as '%s'"
                " — a message the honest client never sent\n",
                nImage, N(kClientAddr).c_str());
    std::fflush(stdout);

    EnterCriticalSection(&g_csToServer);
    bool ok = (g_sToServer != INVALID_SOCKET) &&
              SendAll(g_sToServer, (const char*)pImage, (int)nImage);
    LeaveCriticalSection(&g_csToServer);
    if (!ok) Log("SETUP: injection send() failed");
    return ok;
}

// =========================================================================
int main(int argc, char* argv[])
{
    short nPort = (argc >= 2) ? (short)atoi(argv[1]) : 7816;
    g_oPorts.nListen = nPort;               // the client dials this (the relay)
    g_oPorts.nServer = (short)(nPort + 1);  // the server actually listens here

    std::printf("=== p2p_authrelay — is the proven identity bound to the channel? ===\n");
    std::printf("Port : %d (relay)  ->  %d (server)\n",
                (int)g_oPorts.nListen, (int)g_oPorts.nServer);
    std::printf("Asserting: a relay cannot borrow an identity proven over it.\n\n");
    std::fflush(stdout);

    InitializeCriticalSection(&g_csToServer);
    g_hHonest   = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hInjected = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hRelayUp  = CreateEvent(NULL, TRUE,  FALSE, NULL);

    if (!StartupP2Pmsg(16)) { Log("SETUP: StartupP2Pmsg() failed"); return 2; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);

    // ---- Provisioning -----------------------------------------------------
    const std::string sSrvKey = TempPath("srvkey");
    const std::string sCliKey = TempPath("clikey");
    const std::string sSrvAcl = TempPath("srvacl");
    const std::string sCliAcl = TempPath("cliacl");

    unsigned char pubSrv[p2pcng::kEcdsaPubLen];
    unsigned char pubCli[p2pcng::kEcdsaPubLen];
    if (!MakeIdentity(sSrvKey, pubSrv) || !MakeIdentity(sCliKey, pubCli))
    { Log("SETUP: identity generation failed"); ScrubTempFiles(); return 2; }
    if (p2pcng::AppendAllowList(sSrvAcl.c_str(), "Relay.Client", pubCli) != p2pcng::IdOk ||
        p2pcng::AppendAllowList(sCliAcl.c_str(), "Relay.Server", pubSrv) != p2pcng::IdOk)
    { Log("SETUP: allow-list provisioning failed"); ScrubTempFiles(); return 2; }

    int nExit = 2;
    {
        RelayHub oServer(kServerAddr, true);
        if (oServer.SetIdentity(sSrvKey.c_str())  != p2pcng::IdOk ||
            oServer.SetAllowList(sSrvAcl.c_str()) != p2pcng::IdOk)
        { Log("SETUP: server auth configuration failed"); ScrubTempFiles(); return 2; }
        oServer.RequireAuth(true);
        //  RequireRevocation(false) since 2026-08-21 (Stage 3 step 19): a hub
        //  that requires auth must now hold a POSITION on revocation, and this
        //  test is not about revocation. Saying so is the documented migration
        //  and it is one line. It does NOT turn revocation off - a list named
        //  anyway is still loaded, still enforced and still fails closed.
        oServer.RequireRevocation ( false );

        HANDLE hServerThread = oServer.SpawnHub();
        if (!hServerThread) { Log("SETUP: server SpawnHub() failed"); return 2; }

        P2PeerConWsa* pSvc = P2PeerConWsa::ServiceFactory(kDomain, g_oPorts.nServer);
        if (!pSvc) { Log("SETUP: ServiceFactory failed"); return 2; }
        oServer.PostP2PeerCon(pSvc);
        Log("server listening, RequireAuth(true), allow-list names Relay.Client only");
        Sleep(500);

        HANDLE hRelayThread = CreateThread(NULL, 0, RelayAccept, NULL, 0, NULL);
        if (!hRelayThread) { Log("SETUP: relay thread failed"); return 2; }

        // ---- Phase 1: positive control ------------------------------------
        Log("--- phase 1: the honest client, connecting THROUGH the relay ---");
        RelayHub oClient(kClientAddr, false);
        if (oClient.SetIdentity(sCliKey.c_str())  != p2pcng::IdOk ||
            oClient.SetAllowList(sCliAcl.c_str()) != p2pcng::IdOk)
        { Log("SETUP: client auth configuration failed"); return 2; }
        oClient.RequireAuth(true);
        oClient.RequireRevocation ( false );

        HANDLE hClientThread = oClient.SpawnHub();
        P2PeerConWsa* pCon =
            P2PeerConWsa::ClientFactory(kServerAddr, L"127.0.0.1", g_oPorts.nListen);
        if (!hClientThread || !pCon) { Log("SETUP: client failed"); return 2; }
        oClient.PostP2PeerCon(pCon);

        if (WaitForSingleObject(g_hHonest, 20000) != WAIT_OBJECT_0)
        {
            std::printf(
              "\nRESULT: INCONCLUSIVE — the honest peer never got through the\n"
              "  relay, so the probe would prove nothing. This is NOT a pass.\n"
              "  Check p2p_authpsk first.\n");
            nExit = 3;
        }
        else
        {
            Log("positive control OK — an authenticated session is live through the relay");

            // ---- Phase 2: the probe ---------------------------------------
            Log("--- phase 2: the relay speaks as the peer it merely carried ---");
            if (!InjectAsClient())
            {
                nExit = 2;
            }
            else
            {
                Log("waiting 10s to see whether the injected frame is dispatched...");
                if (WaitForSingleObject(g_hInjected, 10000) == WAIT_OBJECT_0)
                {
                    std::printf(
                      "\nRESULT: FAIL — A RELAY CAN BORROW AN AUTHENTICATED\n"
                      "  IDENTITY.\n"
                      "  The honest client proved itself with a real signature;\n"
                      "  the relay forwarded that proof untouched and then spoke\n"
                      "  in its name. It holds no key, forged nothing and\n"
                      "  replayed nothing — the login it carried was fresh,\n"
                      "  single-use and correctly addressed. Every check passed\n"
                      "  because the signature binds the login MESSAGE and not\n"
                      "  the CHANNEL it arrived on.\n"
                      "  Fix: a session key exchange, with the login signature\n"
                      "  covering its transcript.\n");
                    nExit = 1;
                }
                else
                {
                    std::printf(
                      "\nRESULT: PASS — the injected frame was not dispatched.\n"
                      "  The honest peer got through; the carrier of its proof\n"
                      "  could not speak in its name.\n");
                    nExit = 0;
                }
            }
        }

        g_bRelayStop = true;
        if (g_sFromClient != INVALID_SOCKET) CLOSESOCK(g_sFromClient);
        if (g_sToServer   != INVALID_SOCKET) CLOSESOCK(g_sToServer);
        if (g_sListen     != INVALID_SOCKET) CLOSESOCK(g_sListen);
        WaitForSingleObject(hRelayThread, 3000);
        CloseHandle(hRelayThread);

        oClient.CloseHub();
        WaitForSingleObject(hClientThread, 3000);
        CloseHandle(hClientThread);

        Log("shutdown begin");
        oServer.CloseHub();
        WaitForSingleObject(hServerThread, 3000);
        CloseHandle(hServerThread);
    }

    CleanupP2Pmsg();
    ScrubTempFiles();
    if (g_hHonest)   { CloseHandle(g_hHonest);   g_hHonest   = NULL; }
    if (g_hInjected) { CloseHandle(g_hInjected); g_hInjected = NULL; }
    if (g_hRelayUp)  { CloseHandle(g_hRelayUp);  g_hRelayUp  = NULL; }
    DeleteCriticalSection(&g_csToServer);
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
