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
// p2p_authspoof.cpp — SECURITY GATE TEST: is a message's source address bound
// to the identity the connection actually authenticated as?
//
// BACKGROUND — why this test exists and p2p_authgate was not enough.
//
//   p2p_authgate proves that an unauthenticated peer cannot reach a handler.
//   That gate is real and works (P2PeerCon.cpp:403, commit c62613a).
//
//   But passing that gate only requires COMPLETING a login — and the login
//   proves nothing about who the peer is:
//
//     * The claimed address is accepted as-is. The only policing is a
//       P2Padomain check at P2PeerCon.cpp:1887-1896, and it is skipped
//       entirely when no domain is configured (`!m_oP2Padomain.IsNull()`),
//       which is the default for the stock factories.
//     * There is no key, no signature, no shared secret. Login is an
//       assertion, not a proof.
//
//   And once past the gate, the address used for routing is read from the
//   MESSAGE, not from the connection:
//
//       PostP2Pmsg ( pMsg->GetSource(), CN_P2PeerMsg, 0, ... )   // :412
//
//   `m_oThatP2Paddr` — the identity the connection logged in as — is not
//   consulted. So a peer that completes a login as "Client" can put any
//   source address it likes on every subsequent message.
//
//   This is SECURITY_REVIEW finding M2 ("source-address spoofing"), and it is
//   the substance of what remains of H6 after c62613a.
//
// ---------------------------------------------------------------------------
// STATUS: this test FAILED (exit 1, source spoofing confirmed) until the fix
// at P2PeerCon.cpp:403+ bound the message source to the logged-in identity.
// It now PASSES and is the regression guard for that fix.
//
// Before the fix:
//   [authspoof] SERVER handler ran; source seen = 'AuthSpoof.Admin'
//   RESULT: FAIL — SOURCE SPOOFING CONFIRMED.
// After:
//   Message source [AuthSpoof.Admin] is not the logged-in identity [AuthSpoof.Client]
//   ADVICE : Connection dropped out
// ---------------------------------------------------------------------------
//
// WHAT IT DOES
//
//   1. Two stock hubs in one process over loopback TCP — exactly the
//      wsa_mesh arrangement, nothing weakened:
//        server  "AuthSpoof.Server"   ServiceFactory(expects "AuthSpoof.Client")
//        client  "AuthSpoof.Client"   ClientFactory
//
//   2. The client completes a NORMAL, legitimate login. It is entitled to the
//      address "AuthSpoof.Client" and to nothing else.
//
//   3. INLINE POSITIVE CONTROL: it first posts an HONEST BCast, sourced
//      "AuthSpoof.Client". This must arrive. Without this step a rejection and
//      a broken transport look identical — both are just silence — and the
//      first version of this test could not tell them apart.
//
//   4. Only then does it post a BCast whose SOURCE claims "AuthSpoof.Admin" —
//      an identity it never authenticated as and has no claim to.
//
//   5. That one must NOT arrive.
//
// VERDICT = process EXIT CODE:
//   0  PASS   honest message arrived, spoofed message did not — source
//             binding is enforced
//   1  FAIL   the handler saw source == "AuthSpoof.Admin"  => SPOOF CONFIRMED
//   2  SETUP  startup / factory failure (test inconclusive)
//   3  INCONCLUSIVE the honest message never arrived — the transport is
//             broken, so the spoof result proves nothing. NOT a pass.
//
// Build (Linux): as p2p_authgate.cpp.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kServerAddr = L"AuthSpoof.Server";
static const P2PaddrSTR kClientAddr = L"AuthSpoof.Client";   // legitimately held
static const P2PaddrSTR kSpoofAddr  = L"AuthSpoof.Admin";    // never authenticated

static HANDLE      g_hHonest  = NULL;    // honest message reached the server
static HANDLE      g_hSpoof   = NULL;    // spoofed message reached the server
static std::string g_strSeenSource;      // last source the server's handler saw

static void Log(const char* msg)
{
    std::printf("[authspoof] %s\n", msg);
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
class SpoofHub : public P2PeerHub
{
public:
    SpoofHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr), m_bServer(bServer), m_bSent(false) {}
    virtual ~SpoofHub() {}

    // Driven from main() so the two posts are strictly ordered: the honest one
    // must be seen to arrive before the spoofed one is even sent.
    void PostAs(P2PaddrSTR strSource, const wchar_t* lpszPayload)
    {
        P2Psize_t nBytes = (P2Psize_t)((wcslen(lpszPayload) + 1) * sizeof(wchar_t));
        PostP2PeerMsg(new P2PeerMsg32(strSource, kServerAddr,
                                      P2Pmsg_BCast, lpszPayload, nBytes));
        std::printf("[authspoof] client posted a BCast sourced '%s'\n",
                    N(strSource).c_str());
        std::fflush(stdout);
    }

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        if (m_bServer)
        {
            g_strSeenSource = pMsg ? N(pMsg->GetSource()) : std::string("<null>");
            std::printf("[authspoof] SERVER handler ran; source seen = '%s'\n",
                        g_strSeenSource.c_str());
            std::fflush(stdout);

            if (g_strSeenSource == "AuthSpoof.Admin")
            { if (g_hSpoof)  SetEvent(g_hSpoof);  }     // the forged identity got through
            else
            { if (g_hHonest) SetEvent(g_hHonest); }     // the positive control landed
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
            Log("client login completed legitimately as 'AuthSpoof.Client'");
            // Positive control first — an honest post over this same connection.
            PostAs(kClientAddr, L"honest");
        }
        return result;
    }

private:
    bool m_bServer;
    bool m_bSent;
};

// =========================================================================
int main(int argc, char* argv[])
{
    short nPort = (argc >= 2) ? (short)atoi(argv[1]) : 7814;

    std::printf("=== p2p_authspoof — source-address binding gate test ===\n");
    std::printf("Port : %d\n", (int)nPort);
    std::printf("Asserting: a message's source must match the authenticated identity.\n\n");
    std::fflush(stdout);

    g_hHonest = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hSpoof  = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16)) { Log("SETUP: StartupP2Pmsg() failed"); return 2; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);

    int nExit = 2;
    {
        SpoofHub oServer(kServerAddr, true);
        SpoofHub oClient(kClientAddr, false);

        //  RequireAuth(false) on both. This test is about the SOURCE-ADDRESS
        //  binding a login does not establish, and it has to run on the
        //  unauthenticated path to say anything: with auth required (the default
        //  since Stage 3 step 8) the impostor is refused at login and the spoof
        //  never reaches the property being tested.
        oServer.RequireAuth ( false );
        oClient.RequireAuth ( false );
        HANDLE hServerThread = oServer.SpawnHub();
        HANDLE hClientThread = oClient.SpawnHub();
        if (!hServerThread || !hClientThread) { Log("SETUP: SpawnHub() failed"); return 2; }

        P2PeerConWsa* pSvc = P2PeerConWsa::ServiceFactory(kClientAddr, nPort);
        if (!pSvc) { Log("SETUP: ServiceFactory failed"); return 2; }
        oServer.PostP2PeerCon(pSvc);
        Log("server listening");

        Sleep(500);   // let the listener bind before dialling

        P2PeerConWsa* pCli = P2PeerConWsa::ClientFactory(kServerAddr, L"127.0.0.1", nPort);
        if (!pCli) { Log("SETUP: ClientFactory failed"); return 2; }
        oClient.PostP2PeerCon(pCli);
        Log("client dialling");

        // ---- Stage 1: the positive control must land --------------------
        if (WaitForSingleObject(g_hHonest, 15000) != WAIT_OBJECT_0)
        {
            std::printf(
              "\nRESULT: INCONCLUSIVE — the HONEST message never reached the\n"
              "  server handler, so the transport is broken and the spoof result\n"
              "  would prove nothing. This is NOT a pass.\n"
              "  Check wsa_mesh; if that is also red, fix that first.\n");
            nExit = 3;
        }
        else
        {
            Log("positive control OK — honest message delivered");

            // ---- Stage 2: the forged one must NOT ------------------------
            oClient.PostAs(kSpoofAddr, L"spoofed");
            Log("waiting 8s to see whether the forged source is accepted...");

            if (WaitForSingleObject(g_hSpoof, 8000) == WAIT_OBJECT_0)
            {
                std::printf(
                  "\nRESULT: FAIL — SOURCE SPOOFING CONFIRMED.\n"
                  "  The server attributed a message to 'AuthSpoof.Admin', an\n"
                  "  identity the peer never authenticated as. The connection had\n"
                  "  logged in as 'AuthSpoof.Client'.\n"
                  "  Routing reads pMsg->GetSource() (P2PeerCon.cpp) without\n"
                  "  consulting m_oThatP2Paddr, the identity the login established.\n"
                  "  See Ahtung_Disaster.md Part 6 and SECURITY.md.\n");
                nExit = 1;
            }
            else
            {
                std::printf(
                  "\nRESULT: PASS — source binding is enforced.\n"
                  "  The honest message ('AuthSpoof.Client') was delivered; the\n"
                  "  forged one ('AuthSpoof.Admin') was not. Expect a\n"
                  "  \"Message source [...] is not the logged-in identity [...]\"\n"
                  "  rejection above, with the connection dropped.\n");
                nExit = 0;
            }
        }

        Log("shutdown begin");
        oClient.CloseHub();
        oServer.CloseHub();
        WaitForSingleObject(hClientThread, 3000);
        WaitForSingleObject(hServerThread, 3000);
        CloseHandle(hClientThread);
        CloseHandle(hServerThread);
    }

    CleanupP2Pmsg();
    if (g_hHonest) { CloseHandle(g_hHonest); g_hHonest = NULL; }
    if (g_hSpoof)  { CloseHandle(g_hSpoof);  g_hSpoof  = NULL; }
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
