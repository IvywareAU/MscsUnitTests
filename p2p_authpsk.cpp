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
// p2p_authpsk.cpp — SECURITY GATE TEST: is the identity claimed at login
// actually PROVEN, or merely asserted?
//
// BACKGROUND — the third gate. It was the one still open when this was
// written; the signed login (P2PAuthLogin.h) has since closed it, and this is
// now the regression guard. Measured 2026-08-14: PASS — "Both peers matched
// the domain 'AuthPsk.*'; only one matched a key."
//
//   p2p_authgate   : an unauthenticated peer cannot reach a handler.     PASSES
//   p2p_authspoof  : a logged-in peer cannot forge its source mid-session. PASSES
//   p2p_authpsk    : a peer cannot claim an identity that is not its own. PASSES
//                                                                        <-- this one
//
//   The first two together mean: every message is attributable to the identity
//   its connection logged in as. They say nothing about whether that identity
//   is real.
//
//   P2PeerCon::OnLogin takes the claimed address off the wire and installs it:
//
//       if ( !oThatP2Paddr.IsNull() )
//         m_oThatP2Paddr = oThatP2Paddr;      // P2PeerCon.cpp
//       SetState ( ConState_Login, 0 );
//
//   The only policing is the P2Padomain check just above it. That check is
//   real and it does fire: P2PeerConWsa::ServiceFactory sets
//   m_oP2Padomain = strP2PaddrThat (P2PeerConWsa.cpp:121), so the service's
//   first argument doubles as the set of addresses a peer may claim. A server
//   that expects exactly one peer is therefore already tight.
//
//   The gap is that a domain is a WILDCARD PATTERN, and any server accepting
//   more than one client needs a broad one — it cannot name every peer up
//   front. Within that pattern there is no key, no signature and no shared
//   secret: every peer that matches the domain may claim every address that
//   matches the domain. Peers in the same domain can freely impersonate one
//   another, which for a multi-peer deployment is the whole population.
//
//   So an attacker does not need to forge a source address (p2p_authspoof
//   closed that): it logs in AS the identity it wants, and every subsequent
//   message is self-consistent and passes every existing check.
//
//   This test therefore uses a WILDCARD domain ("AuthPsk.*") — the realistic
//   multi-peer configuration. Against a single-address domain the existing
//   check already refuses the impostor, which is worth knowing but is not the
//   configuration most deployments can use.
//
// ---------------------------------------------------------------------------
// THIS TEST FAILED BY DESIGN UNTIL THE SIGNED LOGIN LANDED (P2PAuthLogin.h).
// It encodes the REQUIREMENT ("a claimed identity must be proven"), not the
// behaviour of any particular commit. If it ever goes red again, peers can
// impersonate one another — do not "fix" it by relaxing the assertion.
// ---------------------------------------------------------------------------
//
// WHAT CLOSED IT. Each hub now holds an ECDSA P-256 identity and an allow-list
// naming the peers it will accept. The login carries a signature over the
// addresses, a nonce and a timestamp; the server verifies it against the
// public point the allow-list already binds to the CLAIMED address. So the
// domain pattern no longer decides anything on its own — the name has to match
// a key.
//
// Note what is deliberately NOT done here: the impostor is given a perfectly
// valid identity of its own. It is refused because the server's allow-list has
// no entry for the name it claims, not because it lacks a key. Handing it a
// key makes the test harder to pass, not easier.
//
// WHAT IT DOES — two sequential phases against one server.
//
//   Phase 1 (POSITIVE CONTROL): a hub at "AuthPsk.Client" — the address the
//   service was told to expect, holding the key the server's allow-list names
//   for it — connects, logs in, and posts. This MUST arrive. Without it, a
//   refusal in phase 2 and a broken transport are indistinguishable; both are
//   silence. It also proves the auth block is stripped: the server's stock
//   On_ConLogin throws on a non-empty login payload, so a block left visible
//   would take phase 1 down with it.
//
//   Phase 2 (THE PROBE): a hub at "AuthPsk.Admin" — an identity it has no
//   claim to — connects, logs in, and posts. Note this peer is entirely
//   self-consistent: it logs in as Admin and sources its messages as Admin, so
//   the source-binding check is satisfied. Only a proof of identity can stop
//   it. This MUST NOT arrive.
//
// VERDICT = process EXIT CODE:
//   0  PASS   phase 1 delivered, phase 2 refused — identity is proven
//   1  FAIL   phase 2 was delivered => ANY PEER CAN CLAIM ANY IDENTITY
//   2  SETUP  startup / factory failure (test inconclusive)
//   3  INCONCLUSIVE phase 1 never arrived — transport broken, proves nothing
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

// ---------------------------------------------------------------------------
static const P2PaddrSTR kServerAddr = L"AuthPsk.Server";
static const P2PaddrSTR kClientAddr = L"AuthPsk.Client";   // legitimately held
static const P2PaddrSTR kAdminAddr  = L"AuthPsk.Admin";    // NOT this peer's to claim
// The service's peer argument is also its accepted-address DOMAIN
// (P2PeerConWsa.cpp:121). A multi-peer server cannot enumerate its clients, so
// it must use a pattern - and every address matching the pattern is claimable
// by every peer matching the pattern.
static const P2PaddrSTR kDomain     = L"AuthPsk.*";

static HANDLE      g_hHonest   = NULL;   // phase 1 landed
static HANDLE      g_hImpostor = NULL;   // phase 2 landed (it must not)

static void Log(const char* msg)
{
    std::printf("[authpsk] %s\n", msg);
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
// Identity provisioning — what an operator would do once, by hand, before
// deploying: generate a key per peer, and publish each peer's PUBLIC point to
// whoever must trust it. Nothing secret crosses between the three hubs here,
// which is the property a shared secret could not have given us.
// ---------------------------------------------------------------------------
static std::vector<std::string> g_vTempFiles;

static std::string TempPath(const char* pszLeaf)
{
    char szDir[MAX_PATH + 2] = { 0 };
    DWORD n = GetTempPathA(MAX_PATH + 1, szDir);
    std::string s = (n > 0 && n <= MAX_PATH) ? std::string(szDir) : std::string(".\\");
    char szPid[32];
    std::snprintf(szPid, sizeof(szPid), "%lu", (unsigned long)GetCurrentProcessId());
    s += "p2p_authpsk_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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

// Generates a key, saves it protected at rest, and hands back its public point.
static bool MakeIdentity(const std::string& sPath, unsigned char* pPubOut)
{
    p2pcng::EcdsaP256 oKey;
    if (!oKey.Generate())                                       return false;
    if (p2pcng::SaveIdentity(sPath.c_str(), oKey) != p2pcng::IdOk) return false;
    return oKey.ExportPublic(pPubOut);
}

// =========================================================================
class PskHub : public P2PeerHub
{
public:
    PskHub(P2PaddrSTR strAddr, bool bServer)
        : P2PeerHub(strAddr), m_bServer(bServer), m_bSent(false)
    { m_strSelf = strAddr; }
    virtual ~PskHub() {}

protected:
    virtual msgRESULT On_P2PeerBCast(P2PeerMsg* pMsg) override
    {
        if (m_bServer)
        {
            std::string src = pMsg ? N(pMsg->GetSource()) : std::string("<null>");
            std::printf("[authpsk] SERVER handler ran; source = '%s'\n", src.c_str());
            std::fflush(stdout);

            if      (src == "AuthPsk.Admin")  { if (g_hImpostor) SetEvent(g_hImpostor); }
            else if (src == "AuthPsk.Client") { if (g_hHonest)   SetEvent(g_hHonest);   }
        }
        return msgHANDLED;
    }

    // The server accepts whatever the peer says it is. Recorded so the log
    // shows the claim being believed.
    virtual conRESULT On_ConLogin(P2PeerCon* pCon, P2PaddrSTR strThatP2Paddr,
                                  const void* pvLoginMsg, P2Psize_t iSize) override
    {
        if (m_bServer)
        {
            std::printf("[authpsk] SERVER accepted a login claiming '%s'"
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
            static const wchar_t* kPayload = L"hello";
            P2Psize_t nBytes = (P2Psize_t)((wcslen(kPayload) + 1) * sizeof(wchar_t));
            // Sourced as ourselves — consistent with our login, so the
            // source-binding check is satisfied. The lie is the login itself.
            PostP2PeerMsg(new P2PeerMsg32(m_strSelf.GetString(), kServerAddr,
                                          P2Pmsg_BCast, kPayload, nBytes));
            std::printf("[authpsk] client '%s' logged in and posted\n",
                        N(m_strSelf.GetString()).c_str());
            std::fflush(stdout);
        }
        return result;
    }

private:
    bool    m_bServer;
    bool    m_bSent;
    CString m_strSelf;
};

// =========================================================================
int main(int argc, char* argv[])
{
    short nPort = (argc >= 2) ? (short)atoi(argv[1]) : 7815;

    std::printf("=== p2p_authpsk — login identity proof gate test ===\n");
    std::printf("Port : %d\n", (int)nPort);
    std::printf("Asserting: a peer cannot claim an identity that is not its own.\n\n");
    std::fflush(stdout);

    g_hHonest   = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hImpostor = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!StartupP2Pmsg(16)) { Log("SETUP: StartupP2Pmsg() failed"); return 2; }
    WSADATA oWsaData;
    WSAStartup(MAKEWORD(2, 2), &oWsaData);

    // ---- Provisioning -----------------------------------------------------
    // Three identities, three private keys that never move, and two allow-lists
    // built from public points only.
    const std::string sSrvKey   = TempPath("srvkey");
    const std::string sCliKey   = TempPath("clikey");
    const std::string sRogueKey = TempPath("roguekey");
    const std::string sSrvAcl   = TempPath("srvacl");
    const std::string sCliAcl   = TempPath("cliacl");
    const std::string sRogueAcl = TempPath("rogueacl");

    unsigned char pubSrv[p2pcng::kEcdsaPubLen];
    unsigned char pubCli[p2pcng::kEcdsaPubLen];
    unsigned char pubRogue[p2pcng::kEcdsaPubLen];
    if (!MakeIdentity(sSrvKey,   pubSrv)   ||
        !MakeIdentity(sCliKey,   pubCli)   ||
        !MakeIdentity(sRogueKey, pubRogue))
    { Log("SETUP: identity generation failed"); ScrubTempFiles(); return 2; }

    // The server trusts exactly one peer, under exactly one name. Note what is
    // NOT here: any entry for AuthPsk.Admin. The domain 'AuthPsk.*' still
    // matches that name — the allow-list is what refuses it.
    if (p2pcng::AppendAllowList(sSrvAcl.c_str(), "AuthPsk.Client", pubCli) != p2pcng::IdOk ||
        p2pcng::AppendAllowList(sCliAcl.c_str(), "AuthPsk.Server", pubSrv) != p2pcng::IdOk ||
        p2pcng::AppendAllowList(sRogueAcl.c_str(), "AuthPsk.Server", pubSrv) != p2pcng::IdOk)
    { Log("SETUP: allow-list provisioning failed"); ScrubTempFiles(); return 2; }

    char szFp[p2pcng::kIdFingerprintLen];
    if (p2pcng::Fingerprint(pubCli, szFp))
        std::printf("[authpsk] server trusts AuthPsk.Client = %s\n", szFp);
    if (p2pcng::Fingerprint(pubRogue, szFp))
        std::printf("[authpsk] impostor holds a valid key   = %s (in nobody's list)\n", szFp);
    std::fflush(stdout);

    int nExit = 2;
    {
        PskHub oServer(kServerAddr, true);
        // Configure BEFORE SpawnHub. RequireAuth is a hub property with no
        // per-connection override — it is the one setting that must not be
        // losable when AcceptSpawn builds the accepted connection.
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

        P2PeerConWsa* pSvc = P2PeerConWsa::ServiceFactory(kDomain, nPort);
        if (!pSvc) { Log("SETUP: ServiceFactory failed"); return 2; }
        oServer.PostP2PeerCon(pSvc);
        Log("server listening (domain 'AuthPsk.*' — the multi-peer configuration)");
        Sleep(500);

        // ---- Phase 1: positive control -----------------------------------
        Log("--- phase 1: legitimate peer 'AuthPsk.Client' ---");
        PskHub oHonest(kClientAddr, false);
        // Mutual: the client proves itself to the server AND checks the
        // server's acknowledgement against the server key it was given.
        if (oHonest.SetIdentity(sCliKey.c_str())  != p2pcng::IdOk ||
            oHonest.SetAllowList(sCliAcl.c_str()) != p2pcng::IdOk)
        { Log("SETUP: honest client auth configuration failed"); return 2; }
        oHonest.RequireAuth(true);
        oHonest.RequireRevocation ( false );

        HANDLE hHonestThread = oHonest.SpawnHub();
        P2PeerConWsa* pHonestCon =
            P2PeerConWsa::ClientFactory(kServerAddr, L"127.0.0.1", nPort);
        if (!hHonestThread || !pHonestCon) { Log("SETUP: honest client failed"); return 2; }
        oHonest.PostP2PeerCon(pHonestCon);

        if (WaitForSingleObject(g_hHonest, 15000) != WAIT_OBJECT_0)
        {
            std::printf(
              "\nRESULT: INCONCLUSIVE — the legitimate peer never got through, so\n"
              "  the transport is broken and phase 2 would prove nothing.\n"
              "  This is NOT a pass. Check wsa_mesh first.\n");
            nExit = 3;
        }
        else
        {
            Log("positive control OK — legitimate peer delivered");

            // ---- Phase 2: the impostor -----------------------------------
            Log("--- phase 2: impostor claiming 'AuthPsk.Admin' ---");
            PskHub oImpostor(kAdminAddr, false);
            // Armed, not disarmed: a real key, correctly protected, and the
            // server's public point so it can check the ack it will never get.
            // Its only deficiency is that no allow-list names it 'AuthPsk.Admin'.
            if (oImpostor.SetIdentity(sRogueKey.c_str())  != p2pcng::IdOk ||
                oImpostor.SetAllowList(sRogueAcl.c_str()) != p2pcng::IdOk)
            { Log("SETUP: impostor auth configuration failed"); return 2; }
            oImpostor.RequireAuth(true);
            oImpostor.RequireRevocation ( false );

            HANDLE hImpostorThread = oImpostor.SpawnHub();
            P2PeerConWsa* pImpostorCon =
                P2PeerConWsa::ClientFactory(kServerAddr, L"127.0.0.1", nPort);
            if (!hImpostorThread || !pImpostorCon) { Log("SETUP: impostor failed"); return 2; }
            oImpostor.PostP2PeerCon(pImpostorCon);

            Log("waiting 10s to see whether the unproven claim is accepted...");
            if (WaitForSingleObject(g_hImpostor, 10000) == WAIT_OBJECT_0)
            {
                std::printf(
                  "\nRESULT: FAIL — ANY PEER IN THE DOMAIN CAN CLAIM ANY\n"
                  "  IDENTITY IN THE DOMAIN.\n"
                  "  A peer with no entitlement logged in as 'AuthPsk.Admin'\n"
                  "  and its message was delivered. The domain pattern\n"
                  "  'AuthPsk.*' was satisfied — and if that is all that was\n"
                  "  checked, then within any domain broad enough to serve\n"
                  "  several peers, those peers can impersonate one another.\n"
                  "  The signed login is supposed to stop exactly this: check\n"
                  "  that RequireAuth(true) is set on the server and that the\n"
                  "  allow-list has no AuthPsk.Admin entry.\n");
                nExit = 1;
            }
            else
            {
                std::printf(
                  "\nRESULT: PASS — the unproven identity claim was refused.\n"
                  "  The legitimate peer got through; the impostor did not.\n"
                  "  Both peers matched the domain 'AuthPsk.*'; only one\n"
                  "  matched a key.\n");
                nExit = 0;
            }

            oImpostor.CloseHub();
            WaitForSingleObject(hImpostorThread, 3000);
            CloseHandle(hImpostorThread);
        }

        oHonest.CloseHub();
        WaitForSingleObject(hHonestThread, 3000);
        CloseHandle(hHonestThread);

        Log("shutdown begin");
        oServer.CloseHub();
        WaitForSingleObject(hServerThread, 3000);
        CloseHandle(hServerThread);
    }

    CleanupP2Pmsg();
    ScrubTempFiles();
    if (g_hHonest)   { CloseHandle(g_hHonest);   g_hHonest   = NULL; }
    if (g_hImpostor) { CloseHandle(g_hImpostor); g_hImpostor = NULL; }
    WSACleanup();

    std::printf("Done (exit=%d).\n", nExit);
    std::fflush(stdout);
    return nExit;
}
