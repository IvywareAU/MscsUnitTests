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
// p2p_revokedist.cpp - SECURITY GATE TEST: can a revocation reach a hub that no
// operator edited?
//
// BACKGROUND - the gap this closes. p2p_keyrotate proved a key can be withdrawn
// on a RUNNING hub: append to the revocation file, ReloadRevocationList(), and
// the peer holding it stops getting in. What it did not touch is how that fact
// travels. The list was a local file, so a compromised key was refused exactly
// where somebody remembered to type it and honoured everywhere else - which for
// a mesh of any size is close to not being revoked at all.
//
// Distribution landed on 2026-08-16 (SetRevocationAuthority / IssueRevocationList
// / ApplyRevocationList) and AuthSelfTest section 19 pins the encoding and the
// refusals at p2pauth::AuthPolicy level. Nothing exercised the P2PeerHub half:
// the three entry points, taken under m_oCSectionHub on a live hub, and the
// consequence that matters - that a peer refused after a list ARRIVES is
// refused on the connection, not just in a data structure.
//
// WHAT IT DOES - six phases. One long-lived server (Bob) that trusts an
// authority it never talks to, and two client peers.
//
//   Phase 1 (POSITIVE CONTROL): Doomed connects. MUST arrive - otherwise every
//   later refusal is indistinguishable from a broken transport.
//   Phase 2 (THE DISTRIBUTION): the authority issues a signed list naming
//   Doomed's key; Bob applies it. MUST report RevOk and exactly one entry added.
//   Phase 3 (THE REFUSAL): Doomed reconnects. MUST NOT arrive - and note that
//   nobody edited Bob's revocation file; the fact arrived over the API.
//   Phase 4 (LIVENESS): Spared connects. MUST arrive, so phase 3 is a
//   revocation rather than a hub that has stopped serving.
//   Phase 5 (MERGED, NEVER SUBSTITUTED): the authority empties its own list and
//   issues a NEWER one that names nobody. Bob applies it. Doomed MUST STILL be
//   refused. This is the property that decides whether a rolled-back or
//   replayed list is a denial of service or merely a no-op - an arriving list
//   may only ever ADD.
//   Phase 6 (NOT MY AUTHORITY): a rogue hub with a perfectly valid identity
//   issues a list naming Spared. Bob MUST refuse it with RevErrIssuer, and
//   Spared MUST still connect. A deny-list any peer can inject is a denial of
//   service, and one compromised peer would otherwise revoke the whole mesh.
//
// VERDICT = process EXIT CODE:
//   0  PASS   all six hold
//   1  FAIL   a distributed revocation did not bind, or an un-revocation did
//   2  SETUP  startup / provisioning failure (test inconclusive)
//   3  INCONCLUSIVE a control did not behave, so the refusals prove nothing

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
static const P2PaddrSTR kServerAddr = L"RevD.Server";
static const P2PaddrSTR kDoomedAddr = L"RevD.Doomed";   // gets revoked
static const P2PaddrSTR kSparedAddr = L"RevD.Spared";   // must not
static const P2PaddrSTR kDomain     = L"RevD.*";

static const wchar_t *kPayDoomed1 = L"doomed-before";
static const wchar_t *kPayDoomed3 = L"doomed-after-revocation";
static const wchar_t *kPayDoomed5 = L"doomed-after-empty-list";
static const wchar_t *kPaySpared4 = L"spared-liveness";
static const wchar_t *kPaySpared6 = L"spared-after-rogue-list";

static HANDLE g_hDoomed1 = NULL;
static HANDLE g_hDoomed3 = NULL;   // must stay unsignalled
static HANDLE g_hDoomed5 = NULL;   // must stay unsignalled
static HANDLE g_hSpared4 = NULL;
static HANDLE g_hSpared6 = NULL;

static void Log ( const char *msg )
{
    std::printf ( "[revokedist] %s\n", msg );
    std::fflush ( stdout );
}

static std::string N ( const wchar_t *w )
{
    std::string s;
    if ( w ) for ( ; *w; ++w )
    {
        unsigned long c = (unsigned long)*w;
        s.push_back ( c < 0x80 ? (char)c : '?' );
    }
    return s;
}

//  THE PAYLOAD POINTER IS NOT ALIGNED, so it cannot be read as wchar_t in
//  place.  P2PeerMsg::Data() addresses the application bytes where they sit
//  inside the packed message image, and that image is pack(1) - a payload
//  begins at whatever offset the block headers and names ahead of it add up
//  to, which is odd about half the time.  Casting it to wchar_t* is undefined
//  behaviour; on Linux, where wchar_t wants 4-byte alignment, it is what UBSan
//  reported as F-S5-3, at this very line.
//    Copying the bytes out into storage the caller aligned is the fix, and it
//  is what the library's own wide accessors have always done internally.
//  See P3PmsgData::c_vBlobCopy() for the same thing offered as an accessor.
static std::wstring BodyW ( P2PeerMsg *pMsg )
{
    if ( !pMsg || !pMsg->Data ( ) ) return std::wstring ( );
    const size_t cb = (size_t)pMsg->DataSize ( );
    std::wstring w ( cb / sizeof(wchar_t), L'\0' );
    if ( !w.empty ( ) )
      std::memcpy ( &w[0], pMsg->Data ( ), w.size ( ) * sizeof(wchar_t) );
    const size_t nNul = w.find ( L'\0' );      // the payloads are literals
    if ( nNul != std::wstring::npos ) w.resize ( nNul );
    return w;
}

// ---------------------------------------------------------------------------
static std::vector<std::string> g_vTempFiles;

static std::string TempPath ( const char *pszLeaf )
{
    char szDir[MAX_PATH + 2] = { 0 };
    DWORD n = GetTempPathA ( MAX_PATH + 1, szDir );
    std::string s = ( n > 0 && n <= MAX_PATH ) ? std::string ( szDir )
                                               : std::string ( ".\\" );
    char szPid[32];
    std::snprintf ( szPid, sizeof(szPid), "%lu",
                    (unsigned long)GetCurrentProcessId ( ) );
    s += "p2p_revokedist_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
    DeleteFileA ( s.c_str ( ) );
    g_vTempFiles.push_back ( s );
    return s;
}

static void ScrubTempFiles ( )
{
    for ( size_t i = 0; i < g_vTempFiles.size ( ); ++i )
        DeleteFileA ( g_vTempFiles[i].c_str ( ) );
    g_vTempFiles.clear ( );
}

static bool MakeIdentity ( const std::string &sPath, unsigned char *pPubOut )
{
    p2pcng::EcdsaP256 oKey;
    if ( !oKey.Generate ( ) ) return false;
    if ( p2pcng::SaveIdentity ( sPath.c_str ( ), oKey ) != p2pcng::IdOk ) return false;
    return oKey.ExportPublic ( pPubOut );
}

// A list that exists and revokes nothing. NOT the same as no file: a configured
// list that cannot be read fails CLOSED and refuses every peer, so this is what
// a deployment with nothing yet revoked holds. It is also what a hub must have
// before it can ACCEPT a distributed list - somewhere durable to put it, rather
// than a merge it would forget at the next restart.
static bool WriteEmptyRevocationList ( const std::string &sPath )
{
    std::FILE *fp = std::fopen ( sPath.c_str ( ), "wb" );
    if ( !fp ) return false;
    std::fputs ( "# Targetcore revocation list - nothing revoked yet\n", fp );
    std::fclose ( fp );
    return true;
}

// =========================================================================
class RevHub : public P2PeerHub
{
public:
    RevHub ( P2PaddrSTR strAddr, bool bServer, const wchar_t *pszPayload )
        : P2PeerHub ( strAddr ), m_bServer ( bServer )
        , m_bSent ( false ), m_pszPayload ( pszPayload )
    { m_strSelf = strAddr; }
    virtual ~RevHub ( ) { }

protected:
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_bServer && pMsg )
        {
            const std::wstring wBody = BodyW ( pMsg );   // copied out, aligned
            std::string sBody = pMsg->Data ( ) ? N ( wBody.c_str ( ) )
                                                : std::string ( "<null>" );
            std::printf ( "[revokedist] SERVER received '%s' from '%s'\n",
                          sBody.c_str ( ), N ( pMsg->GetSource ( ) ).c_str ( ) );
            std::fflush ( stdout );

            if      ( sBody == N ( kPayDoomed1 ) ) { if ( g_hDoomed1 ) SetEvent ( g_hDoomed1 ); }
            else if ( sBody == N ( kPayDoomed3 ) ) { if ( g_hDoomed3 ) SetEvent ( g_hDoomed3 ); }
            else if ( sBody == N ( kPayDoomed5 ) ) { if ( g_hDoomed5 ) SetEvent ( g_hDoomed5 ); }
            else if ( sBody == N ( kPaySpared4 ) ) { if ( g_hSpared4 ) SetEvent ( g_hSpared4 ); }
            else if ( sBody == N ( kPaySpared6 ) ) { if ( g_hSpared6 ) SetEvent ( g_hSpared6 ); }
        }
        return msgHANDLED;
    }

    virtual conRESULT On_ConLoginAck ( P2PeerCon  *pCon,
                                       P2PaddrSTR  strThisP2Paddr,
                                       P2PaddrSTR  strThatP2Paddr,
                                       const void *pvLoginAck,
                                       P2Psize_t   iSize ) override
    {
        conRESULT result = P2PeerHub::On_ConLoginAck ( pCon, strThisP2Paddr,
                                                       strThatP2Paddr,
                                                       pvLoginAck, iSize );
        if ( !m_bServer && !m_bSent && m_pszPayload )
        {
            m_bSent = true;
            P2Psize_t nBytes =
                (P2Psize_t)( ( wcslen ( m_pszPayload ) + 1 ) * sizeof(wchar_t) );
            PostP2PeerMsg ( new P2PeerMsg32 ( m_strSelf.GetString ( ), kServerAddr,
                                              P2Pmsg_BCast, m_pszPayload, nBytes ) );
        }
        return result;
    }

private:
    bool           m_bServer;
    bool           m_bSent;
    const wchar_t *m_pszPayload;
    CString        m_strSelf;
};

// -------------------------------------------------------------------------
//  One client attempt. Same shape as p2p_keyrotate: stand the hub up, wait for
//  its message to reach the server, tear it down - the hub is always closed,
//  arrival or not, because the next attempt reuses the address
// -------------------------------------------------------------------------
static bool RunPeer ( P2PaddrSTR strAddr, const std::string &sKeyFile,
                      const std::string &sAcl, const wchar_t *pszPayload,
                      HANDLE hEvent, short nPort, DWORD dwWaitMs,
                      bool *pbSetupFailed )
{
    *pbSetupFailed = false;

    RevHub oPeer ( strAddr, false, pszPayload );
    if ( oPeer.SetIdentity  ( sKeyFile.c_str ( ) ) != p2pcng::IdOk ||
         oPeer.SetAllowList ( sAcl    .c_str ( ) ) != p2pcng::IdOk )
    { *pbSetupFailed = true; return false; }
    oPeer.RequireAuth ( true );
    //  RequireRevocation(false) since 2026-08-21 (Stage 3 step 19): a hub
    //  that requires auth must now hold a POSITION on revocation, and this
    //  test is not about revocation. Saying so is the documented migration
    //  and it is one line. It does NOT turn revocation off - a list named
    //  anyway is still loaded, still enforced and still fails closed.
    oPeer.RequireRevocation ( false );

    HANDLE hThread = oPeer.SpawnHub ( );
    P2PeerConWsa *pCon =
        P2PeerConWsa::ClientFactory ( kServerAddr, L"127.0.0.1", nPort );
    if ( !hThread || !pCon ) { *pbSetupFailed = true; return false; }
    oPeer.PostP2PeerCon ( pCon );

    bool bArrived = ( WaitForSingleObject ( hEvent, dwWaitMs ) == WAIT_OBJECT_0 );

    oPeer.CloseHub ( );
    WaitForSingleObject ( hThread, 3000 );
    CloseHandle ( hThread );
    Sleep ( 300 );
    return bArrived;
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7830;

    std::printf ( "=== p2p_revokedist - revocation distribution gate test ===\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::printf ( "Asserting: a revocation reaches a hub nobody edited, and\n"
                  "           nothing that arrives can un-revoke anything.\n\n" );
    std::fflush ( stdout );

    g_hDoomed1 = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hDoomed3 = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hDoomed5 = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hSpared4 = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hSpared6 = CreateEvent ( NULL, FALSE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    // ---- Provisioning -----------------------------------------------------
    const std::string sSrvKey  = TempPath ( "srvkey"  );
    const std::string sDoomKey = TempPath ( "doomkey" );
    const std::string sSparKey = TempPath ( "sparkey" );
    const std::string sAuthKey = TempPath ( "authkey" );   // the authority
    const std::string sRogueKey= TempPath ( "roguekey" );  // a valid stranger
    const std::string sSrvAcl  = TempPath ( "srvacl"  );
    const std::string sCliAcl  = TempPath ( "cliacl"  );
    const std::string sSrvRev  = TempPath ( "srvrev"  );   // Bob's own file
    const std::string sAuthRev = TempPath ( "authrev" );   // the authority's
    const std::string sRogueRev= TempPath ( "roguerev" );

    unsigned char pubSrv[p2pcng::kEcdsaPubLen];
    unsigned char pubDoom[p2pcng::kEcdsaPubLen];
    unsigned char pubSpar[p2pcng::kEcdsaPubLen];
    unsigned char pubAuth[p2pcng::kEcdsaPubLen];
    unsigned char pubRogue[p2pcng::kEcdsaPubLen];
    if ( !MakeIdentity ( sSrvKey,  pubSrv  ) ||
         !MakeIdentity ( sDoomKey, pubDoom ) ||
         !MakeIdentity ( sSparKey, pubSpar ) ||
         !MakeIdentity ( sAuthKey, pubAuth ) ||
         !MakeIdentity ( sRogueKey,pubRogue ) )
    { Log ( "SETUP: identity generation failed" ); ScrubTempFiles ( ); return 2; }

    if ( p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "RevD.Doomed", pubDoom ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "RevD.Spared", pubSpar ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sCliAcl.c_str ( ), "RevD.Server", pubSrv  ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( ); return 2; }

    // Three revocation files. Bob's starts empty - the whole point is that
    // nothing is ever typed into it. The authority's carries Doomed's key.
    if ( !WriteEmptyRevocationList ( sSrvRev   ) ||
         !WriteEmptyRevocationList ( sAuthRev  ) ||
         !WriteEmptyRevocationList ( sRogueRev ) )
    { Log ( "SETUP: revocation file creation failed" ); ScrubTempFiles ( ); return 2; }

    if ( p2pcng::AppendRevocationList ( sAuthRev.c_str ( ), pubDoom, 0,
                                        "compromised, per p2p_revokedist" )
             != p2pcng::IdOk ||
         p2pcng::AppendRevocationList ( sRogueRev.c_str ( ), pubSpar, 0,
                                        "a lie told by a stranger" )
             != p2pcng::IdOk )
    { Log ( "SETUP: revocation provisioning failed" ); ScrubTempFiles ( ); return 2; }

    int nExit = 2;
    {
        // ---- Bob: trusts an authority it never connects to ----------------
        RevHub oServer ( kServerAddr, true, 0 );
        if ( oServer.SetIdentity       ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
             oServer.SetAllowList      ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk ||
             oServer.SetRevocationList ( sSrvRev.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: server auth configuration failed" ); ScrubTempFiles ( ); return 2; }
        if ( oServer.SetRevocationAuthority ( pubAuth ) != p2pcng::IdOk ||
             !oServer.HasRevocationAuthority ( ) )
        { Log ( "SETUP: SetRevocationAuthority failed" ); ScrubTempFiles ( ); return 2; }
        oServer.RequireAuth ( true );
        oServer.RequireRevocation ( false );
        if ( !oServer.IsRevocationUsable ( ) )
        { Log ( "SETUP: revocation list did not load" ); ScrubTempFiles ( ); return 2; }

        HANDLE hServerThread = oServer.SpawnHub ( );
        if ( !hServerThread ) { Log ( "SETUP: server SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        oServer.PostP2PeerCon ( pSvc );
        Log ( "server listening; its own revocation file is EMPTY" );
        Sleep ( 500 );

        bool bSetup = false;

        // ---- Phase 1: positive control ------------------------------------
        Log ( "--- phase 1: Doomed connects, before anything is revoked ---" );
        const bool b1 = RunPeer ( kDoomedAddr, sDoomKey, sCliAcl, kPayDoomed1,
                                  g_hDoomed1, nPort, 15000, &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 1 peer failed" ); return 2; }

        if ( !b1 )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the legitimate peer never got through, so\n"
              "  the transport is broken and the later phases prove nothing.\n"
              "  Check wsa_mesh and p2p_authpsk first.\n" );
            nExit = 3;
        }
        else
        {
            Log ( "positive control OK" );

            // ---- Phase 2: issue and apply ---------------------------------
            Log ( "--- phase 2: the authority issues, Bob applies ---" );
            bool bDist = false;
            size_t nAdded = 0;
            {
                RevHub oAuthority ( L"RevD.Authority", false, 0 );
                if ( oAuthority.SetIdentity       ( sAuthKey.c_str ( ) ) != p2pcng::IdOk ||
                     oAuthority.SetRevocationList ( sAuthRev.c_str ( ) ) != p2pcng::IdOk )
                { Log ( "SETUP: authority configuration failed" ); return 2; }

                std::vector<unsigned char> vList ( 64 * 1024, 0 );
                size_t cbOut = 0;
                const p2pauth::RevResult eIssue =
                    oAuthority.IssueRevocationList ( 1, &vList[0], vList.size ( ), &cbOut );
                std::printf ( "[revokedist] IssueRevocationList: %s (%u bytes)\n",
                              p2pauth::RevResultText ( eIssue ), (unsigned)cbOut );

                if ( eIssue == p2pauth::RevOk )
                {
                    const p2pauth::RevResult eApply =
                        oServer.ApplyRevocationList ( &vList[0], cbOut, &nAdded );
                    std::printf ( "[revokedist] ApplyRevocationList: %s (%u added, epoch %lld)\n",
                                  p2pauth::RevResultText ( eApply ), (unsigned)nAdded,
                                  (long long)oServer.RevocationEpoch ( ) );
                    bDist = ( eApply == p2pauth::RevOk && nAdded == 1 );
                }
                std::fflush ( stdout );
            }

            if ( !bDist )
            {
                std::printf (
                  "\nRESULT: FAIL - THE SIGNED LIST DID NOT APPLY.\n"
                  "  The authority issued a list naming one key and Bob did not\n"
                  "  take it (or took it and added something other than one\n"
                  "  entry). Distribution is the whole feature: without it a\n"
                  "  compromised key is refused only where an operator\n"
                  "  remembered to type it.\n" );
                nExit = 1;
            }
            else
            {
                // ---- Phase 3: the refusal -----------------------------
                Log ( "--- phase 3: Doomed reconnects (nobody edited Bob's file) ---" );
                const bool b3 = RunPeer ( kDoomedAddr, sDoomKey, sCliAcl, kPayDoomed3,
                                          g_hDoomed3, nPort, 10000, &bSetup );
                if ( bSetup ) { Log ( "SETUP: phase 3 peer failed" ); return 2; }

                // ---- Phase 4: liveness --------------------------------
                Log ( "--- phase 4: Spared connects (liveness) ---" );
                const bool b4 = RunPeer ( kSparedAddr, sSparKey, sCliAcl, kPaySpared4,
                                          g_hSpared4, nPort, 15000, &bSetup );
                if ( bSetup ) { Log ( "SETUP: phase 4 peer failed" ); return 2; }

                // ---- Phase 5: merged, never substituted ---------------
                Log ( "--- phase 5: a NEWER list naming nobody must not un-revoke ---" );
                bool bEmptyApplied = false;
                {
                    if ( !WriteEmptyRevocationList ( sAuthRev ) )
                    { Log ( "SETUP: could not empty the authority's list" ); return 2; }

                    RevHub oAuthority ( L"RevD.Authority2", false, 0 );
                    if ( oAuthority.SetIdentity       ( sAuthKey.c_str ( ) ) != p2pcng::IdOk ||
                         oAuthority.SetRevocationList ( sAuthRev.c_str ( ) ) != p2pcng::IdOk )
                    { Log ( "SETUP: authority reconfiguration failed" ); return 2; }

                    std::vector<unsigned char> vList ( 64 * 1024, 0 );
                    size_t cbOut = 0, nAdded2 = 0;
                    const p2pauth::RevResult eIssue =
                        oAuthority.IssueRevocationList ( 2, &vList[0], vList.size ( ), &cbOut );
                    if ( eIssue == p2pauth::RevOk )
                    {
                        const p2pauth::RevResult eApply =
                            oServer.ApplyRevocationList ( &vList[0], cbOut, &nAdded2 );
                        std::printf ( "[revokedist] empty list at epoch 2: %s (%u added)\n",
                                      p2pauth::RevResultText ( eApply ), (unsigned)nAdded2 );
                        bEmptyApplied = ( eApply == p2pauth::RevOk );
                    }
                    std::fflush ( stdout );
                }

                const bool b5 = RunPeer ( kDoomedAddr, sDoomKey, sCliAcl, kPayDoomed5,
                                          g_hDoomed5, nPort, 10000, &bSetup );
                if ( bSetup ) { Log ( "SETUP: phase 5 peer failed" ); return 2; }

                // ---- Phase 6: not my authority ------------------------
                Log ( "--- phase 6: a list from a stranger must be refused ---" );
                p2pauth::RevResult eRogue = p2pauth::RevErrInternal;
                {
                    RevHub oRogue ( L"RevD.Rogue", false, 0 );
                    if ( oRogue.SetIdentity       ( sRogueKey.c_str ( ) ) != p2pcng::IdOk ||
                         oRogue.SetRevocationList ( sRogueRev.c_str ( ) ) != p2pcng::IdOk )
                    { Log ( "SETUP: rogue configuration failed" ); return 2; }

                    std::vector<unsigned char> vList ( 64 * 1024, 0 );
                    size_t cbOut = 0;
                    if ( oRogue.IssueRevocationList ( 3, &vList[0], vList.size ( ), &cbOut )
                             == p2pauth::RevOk )
                        eRogue = oServer.ApplyRevocationList ( &vList[0], cbOut, 0 );
                    std::printf ( "[revokedist] rogue list: %s\n",
                                  p2pauth::RevResultText ( eRogue ) );
                    std::fflush ( stdout );
                }

                const bool b6 = RunPeer ( kSparedAddr, sSparKey, sCliAcl, kPaySpared6,
                                          g_hSpared6, nPort, 15000, &bSetup );
                if ( bSetup ) { Log ( "SETUP: phase 6 peer failed" ); return 2; }

                // ---- Verdict ------------------------------------------
                if ( b3 )
                {
                    std::printf (
                      "\nRESULT: FAIL - A DISTRIBUTED REVOCATION DOES NOT BIND.\n"
                      "  Bob applied a signed list naming Doomed's key and then let\n"
                      "  Doomed log in anyway. The list is being stored and not\n"
                      "  consulted, which is worse than not having it: an operator\n"
                      "  would believe the key was withdrawn.\n" );
                    nExit = 1;
                }
                else if ( !b4 )
                {
                    std::printf (
                      "\nRESULT: INCONCLUSIVE - Doomed was refused, but so was\n"
                      "  Spared, who was never named in any list. The hub may have\n"
                      "  stopped accepting anything, in which case phase 3 proves\n"
                      "  nothing - a dead hub and a working revocation are both\n"
                      "  silence. Check the merge revokes the POINT, not the file.\n" );
                    nExit = 3;
                }
                else if ( !bEmptyApplied )
                {
                    std::printf (
                      "\nRESULT: INCONCLUSIVE - the newer, empty list would not\n"
                      "  apply at all, so phase 5 did not test what it exists to\n"
                      "  test. A list that adds nothing is still a valid list.\n" );
                    nExit = 3;
                }
                else if ( b5 )
                {
                    std::printf (
                      "\nRESULT: FAIL - AN ARRIVING LIST UN-REVOKED A KEY.\n"
                      "  A newer list naming nobody was applied and Doomed logged\n"
                      "  in again. Distribution must MERGE, never substitute: a\n"
                      "  stale, replayed or rolled-back list may only ever fail to\n"
                      "  add, because the alternative is that anyone who can hand\n"
                      "  a hub an old list can restore a compromised key.\n" );
                    nExit = 1;
                }
                else if ( eRogue != p2pauth::RevErrIssuer )
                {
                    std::printf (
                      "\nRESULT: FAIL - A LIST FROM THE WRONG ISSUER WAS NOT\n"
                      "  REFUSED AS SUCH (got %s, wanted RevErrIssuer).\n"
                      "  A deny-list any peer can inject is a denial of service:\n"
                      "  one compromised peer would revoke the whole mesh. The\n"
                      "  signature must be checked against the ONE configured\n"
                      "  authority, never against the allow-list.\n",
                      p2pauth::RevResultText ( eRogue ) );
                    nExit = 1;
                }
                else if ( !b6 )
                {
                    std::printf (
                      "\nRESULT: FAIL - THE ROGUE LIST TOOK EFFECT ANYWAY.\n"
                      "  Bob reported it refused and then declined the peer it\n"
                      "  named. A refusal that still applies the contents is the\n"
                      "  worst of both.\n" );
                    nExit = 1;
                }
                else
                {
                    std::printf (
                      "\nRESULT: PASS - distribution binds, and only ever adds.\n"
                      "  A signed list from the configured authority reached a hub\n"
                      "  whose own file nobody touched, and the key it named stopped\n"
                      "  getting in (phases 2, 3), while an unnamed peer carried on\n"
                      "  (phase 4).\n"
                      "  A NEWER list naming nobody did not restore it (phase 5).\n"
                      "  A list signed by a valid stranger was refused as\n"
                      "  RevErrIssuer and changed nothing (phase 6).\n" );
                    nExit = 0;
                }
            }
        }

        Log ( "shutdown begin" );
        oServer.CloseHub ( );
        WaitForSingleObject ( hServerThread, 3000 );
        CloseHandle ( hServerThread );
    }

    CleanupP2Pmsg ( );
    ScrubTempFiles ( );
    if ( g_hDoomed1 ) CloseHandle ( g_hDoomed1 );
    if ( g_hDoomed3 ) CloseHandle ( g_hDoomed3 );
    if ( g_hDoomed5 ) CloseHandle ( g_hDoomed5 );
    if ( g_hSpared4 ) CloseHandle ( g_hSpared4 );
    if ( g_hSpared6 ) CloseHandle ( g_hSpared6 );
    WSACleanup ( );

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
