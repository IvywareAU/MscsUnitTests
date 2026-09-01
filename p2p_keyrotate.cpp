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
// p2p_keyrotate.cpp - SECURITY GATE TEST: can a peer's key be REPLACED, and can
// one be WITHDRAWN, on a running deployment?
//
// BACKGROUND - the gap this closes. The signed login (p2p_authpsk) proved an
// identity is real. It said nothing about what happens when that identity's key
// has to change, and SECURITY.md's roadmap carried the consequence in the open
// for four sessions: "Key rotation and revocation - Not implemented, for either
// key kind". Two concrete failures sat behind that line:
//
//   * FindPeer returned the FIRST allow-list entry matching an address, so a
//     second line for the same peer was, in P2PIdentityStore.h's own words,
//     dead weight. Replacing a key therefore meant editing every server that
//     trusts the peer in the same instant the peer cut over - a flag day per
//     rotation, which in practice means the key is never rotated.
//   * There was no way to withdraw a key at all. A compromised peer stayed
//     trusted until someone hand-edited it out of every allow-list, and there
//     was nothing that said "this key, never again" independently of the file
//     that grants it.
//
// The second is what makes the first safe. Rotation on its own only ever ADDS
// trust: two keys where there was one, and no way to get back to one. They are
// a single feature and this test covers them as one.
//
// WHAT IT DOES - four phases against ONE long-lived server, over real TCP. The
// server's allow-list carries TWO lines for "KeyRot.Client": an old key and a
// new one. Its revocation list starts valid and empty.
//
//   Phase 1 (POSITIVE CONTROL): the client connects holding the OLD key. This
//   MUST arrive. A peer mid-rollover is not locked out - and without this,
//   every later refusal is indistinguishable from a broken transport.
//
//   Phase 2 (THE ROTATION): the client reconnects holding the NEW key. This
//   MUST arrive. It is the half that could not work before: the new key sits on
//   the second line, and only the first was ever tried.
//
//   Phase 3 (THE REVOCATION): the OLD key is appended to the revocation list
//   and ReloadRevocationList() is called on the RUNNING server - no restart,
//   which is the only way revocation is of any use during an incident. The
//   client reconnects holding the OLD key. This MUST NOT arrive, even though
//   the allow-list still names it.
//
//   Phase 4 (LIVENESS): the client reconnects holding the NEW key. This MUST
//   arrive. Without it, phase 3 proves nothing - a server that has fallen over
//   also refuses everything, and "revoked" and "dead" are both silence.
//
// All four clients claim the SAME address, so what is under test is purely
// WHICH KEY the server will accept for it. They are run strictly one at a time
// and each hub is closed before the next opens, because a hub refuses a second
// connection from an address it already holds.
//
// VERDICT = process EXIT CODE:
//   0  PASS   1 and 2 delivered, 3 refused, 4 delivered
//   1  FAIL   the revoked key was accepted, or a listed key was refused
//   2  SETUP  startup / provisioning failure (test inconclusive)
//   3  INCONCLUSIVE phase 1 never arrived - transport broken, proves nothing
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
static const P2PaddrSTR kServerAddr = L"KeyRot.Server";
static const P2PaddrSTR kClientAddr = L"KeyRot.Client";   // all four clients
static const P2PaddrSTR kDomain     = L"KeyRot.*";

// Every client claims the same address, so the source cannot tell the phases
// apart. The payload does.
static const wchar_t *kPayOld1 = L"phase1-old";
static const wchar_t *kPayNew2 = L"phase2-new";
static const wchar_t *kPayOld3 = L"phase3-old-revoked";
static const wchar_t *kPayNew4 = L"phase4-new-liveness";

static HANDLE g_hPhase1 = NULL;
static HANDLE g_hPhase2 = NULL;
static HANDLE g_hPhase3 = NULL;   // must stay unsignalled
static HANDLE g_hPhase4 = NULL;

static void Log ( const char *msg )
{
    std::printf ( "[keyrotate] %s\n", msg );
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
// Provisioning - what an operator does by hand. Nothing secret ever moves
// between hubs: each holds its own private key and publishes only its point.
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
    s += "p2p_keyrotate_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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

// A revocation list that exists and revokes nothing. NOT the same as no file:
// a configured list that cannot be read fails CLOSED and refuses every peer, so
// the empty-but-valid file is what a deployment with nothing yet revoked holds.
static bool MakeEmptyRevocationList ( const std::string &sPath )
{
    std::FILE *fp = std::fopen ( sPath.c_str ( ), "wb" );
    if ( !fp ) return false;
    std::fputs ( "# TargetCore revocation list - nothing revoked yet\n", fp );
    std::fclose ( fp );
    return true;
}

// =========================================================================
class RotHub : public P2PeerHub
{
public:
    RotHub ( P2PaddrSTR strAddr, bool bServer, const wchar_t *pszPayload )
        : P2PeerHub ( strAddr ), m_bServer ( bServer )
        , m_bSent ( false ), m_pszPayload ( pszPayload )
    { m_strSelf = strAddr; }
    virtual ~RotHub ( ) {}

protected:
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_bServer && pMsg )
        {
            const std::wstring wBody = BodyW ( pMsg );   // copied out, aligned
            std::string sSrc  = N ( pMsg->GetSource ( ) );
            std::string sBody = pMsg->Data ( ) ? N ( wBody.c_str ( ) )
                                               : std::string ( "<null>" );
            std::printf ( "[keyrotate] SERVER handler ran; source='%s' body='%s'\n",
                          sSrc.c_str ( ), sBody.c_str ( ) );
            std::fflush ( stdout );

            if      ( sBody == N ( kPayOld1 ) ) { if ( g_hPhase1 ) SetEvent ( g_hPhase1 ); }
            else if ( sBody == N ( kPayNew2 ) ) { if ( g_hPhase2 ) SetEvent ( g_hPhase2 ); }
            else if ( sBody == N ( kPayOld3 ) ) { if ( g_hPhase3 ) SetEvent ( g_hPhase3 ); }
            else if ( sBody == N ( kPayNew4 ) ) { if ( g_hPhase4 ) SetEvent ( g_hPhase4 ); }
        }
        return msgHANDLED;
    }

    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        if ( m_bServer )
        {
            std::printf ( "[keyrotate] SERVER accepted a login claiming '%s'\n",
                          N ( strThatP2Paddr ).c_str ( ) );
            std::fflush ( stdout );
        }
        return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );
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
            std::printf ( "[keyrotate] client logged in and posted '%s'\n",
                          N ( m_pszPayload ).c_str ( ) );
            std::fflush ( stdout );
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
// One phase: stand a client up on the given key file, wait for its message to
// reach the server, tear it down again. Returns true if the message arrived.
// The hub is always closed, arrival or not, because the next phase reuses the
// same address and a hub refuses a second connection from one it already holds.
// -------------------------------------------------------------------------
static bool RunPhase ( const std::string &sKeyFile, const std::string &sCliAcl,
                       const wchar_t *pszPayload, HANDLE hEvent,
                       short nPort, DWORD dwWaitMs, bool *pbSetupFailed )
{
    *pbSetupFailed = false;

    RotHub oClient ( kClientAddr, false, pszPayload );
    if ( oClient.SetIdentity  ( sKeyFile.c_str ( ) ) != p2pcng::IdOk ||
         oClient.SetAllowList ( sCliAcl .c_str ( ) ) != p2pcng::IdOk )
    { *pbSetupFailed = true; return false; }
    oClient.RequireAuth ( true );
    //  RequireRevocation(false) since 2026-08-21 (Stage 3 step 19): a hub
    //  that requires auth must now hold a POSITION on revocation, and this
    //  test is not about revocation. Saying so is the documented migration
    //  and it is one line. It does NOT turn revocation off - a list named
    //  anyway is still loaded, still enforced and still fails closed.
    oClient.RequireRevocation ( false );

    HANDLE hThread = oClient.SpawnHub ( );
    P2PeerConWsa *pCon =
        P2PeerConWsa::ClientFactory ( kServerAddr, L"127.0.0.1", nPort );
    if ( !hThread || !pCon ) { *pbSetupFailed = true; return false; }
    oClient.PostP2PeerCon ( pCon );

    bool bArrived = ( WaitForSingleObject ( hEvent, dwWaitMs ) == WAIT_OBJECT_0 );

    oClient.CloseHub ( );
    WaitForSingleObject ( hThread, 3000 );
    CloseHandle ( hThread );
    Sleep ( 300 );                       // let the server drop its side
    return bArrived;
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7824;

    std::printf ( "=== p2p_keyrotate - key rotation and revocation gate test ===\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::printf ( "Asserting: a peer's key can be replaced without a flag day,\n"
                  "           and withdrawn without a restart.\n\n" );
    std::fflush ( stdout );

    g_hPhase1 = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hPhase2 = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hPhase3 = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hPhase4 = CreateEvent ( NULL, FALSE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    // ---- Provisioning -----------------------------------------------------
    const std::string sSrvKey = TempPath ( "srvkey" );
    const std::string sOldKey = TempPath ( "oldkey" );
    const std::string sNewKey = TempPath ( "newkey" );
    const std::string sSrvAcl = TempPath ( "srvacl" );
    const std::string sCliAcl = TempPath ( "cliacl" );
    const std::string sRevoke = TempPath ( "revoke" );

    unsigned char pubSrv[p2pcng::kEcdsaPubLen];
    unsigned char pubOld[p2pcng::kEcdsaPubLen];
    unsigned char pubNew[p2pcng::kEcdsaPubLen];
    if ( !MakeIdentity ( sSrvKey, pubSrv ) ||
         !MakeIdentity ( sOldKey, pubOld ) ||
         !MakeIdentity ( sNewKey, pubNew ) )
    { Log ( "SETUP: identity generation failed" ); ScrubTempFiles ( ); return 2; }

    // TWO lines for one address - the rollover state. Old first, because that
    // is the order appending produces, and the order that used to mean the new
    // key was never reached.
    if ( p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "KeyRot.Client", pubOld ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "KeyRot.Client", pubNew ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sCliAcl.c_str ( ), "KeyRot.Server", pubSrv ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( ); return 2; }

    if ( !MakeEmptyRevocationList ( sRevoke ) )
    { Log ( "SETUP: revocation list creation failed" ); ScrubTempFiles ( ); return 2; }

    char szFp[p2pcng::kIdFingerprintLen];
    if ( p2pcng::Fingerprint ( pubOld, szFp ) )
        std::printf ( "[keyrotate] KeyRot.Client old key = %s\n", szFp );
    if ( p2pcng::Fingerprint ( pubNew, szFp ) )
        std::printf ( "[keyrotate] KeyRot.Client new key = %s\n", szFp );
    std::fflush ( stdout );

    int nExit = 2;
    {
        RotHub oServer ( kServerAddr, true, 0 );
        if ( oServer.SetIdentity       ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
             oServer.SetAllowList      ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk ||
             oServer.SetRevocationList ( sRevoke.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: server auth configuration failed" ); ScrubTempFiles ( ); return 2; }
        oServer.RequireAuth ( true );
        oServer.RequireRevocation ( false );
        if ( !oServer.IsRevocationUsable ( ) )
        { Log ( "SETUP: revocation list did not load" ); ScrubTempFiles ( ); return 2; }

        HANDLE hServerThread = oServer.SpawnHub ( );
        if ( !hServerThread ) { Log ( "SETUP: server SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        oServer.PostP2PeerCon ( pSvc );
        Log ( "server listening; allow-list holds TWO keys for KeyRot.Client" );
        Sleep ( 500 );

        bool bSetup = false;

        // ---- Phase 1: positive control, the OLD key --------------------
        Log ( "--- phase 1: client presents the OLD key (must be accepted) ---" );
        bool b1 = RunPhase ( sOldKey, sCliAcl, kPayOld1, g_hPhase1, nPort, 15000, &bSetup );
        if ( bSetup ) { Log ( "SETUP: phase 1 client failed" ); return 2; }

        if ( !b1 )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the legitimate peer never got through, so\n"
              "  the transport is broken and the later phases prove nothing.\n"
              "  This is NOT a pass. Check wsa_mesh and p2p_authpsk first.\n" );
            nExit = 3;
        }
        else
        {
            Log ( "positive control OK - old key accepted" );

            // ---- Phase 2: the rotation, the NEW key --------------------
            Log ( "--- phase 2: client presents the NEW key (must be accepted) ---" );
            bool b2 = RunPhase ( sNewKey, sCliAcl, kPayNew2, g_hPhase2, nPort, 15000, &bSetup );
            if ( bSetup ) { Log ( "SETUP: phase 2 client failed" ); return 2; }

            if ( !b2 )
            {
                std::printf (
                  "\nRESULT: FAIL - THE SECOND KEY LISTED FOR A PEER IS NOT HONOURED.\n"
                  "  The allow-list names two keys for KeyRot.Client and only the\n"
                  "  first works, so a peer cannot be issued its next key before it\n"
                  "  starts using one. That makes every rotation a flag day across\n"
                  "  every server that trusts the peer - which is how keys end up\n"
                  "  never being rotated at all. Check that AuthPolicy tries EVERY\n"
                  "  matching allow-list entry rather than the first.\n" );
                nExit = 1;
            }
            else
            {
                Log ( "rotation OK - both listed keys accepted" );

                // ---- Phase 3: revoke the old key, live ------------------
                Log ( "--- phase 3: revoking the OLD key on the RUNNING server ---" );
                if ( p2pcng::AppendRevocationList ( sRevoke.c_str ( ), pubOld, 0,
                                                    "rotated out by p2p_keyrotate" )
                         != p2pcng::IdOk )
                { Log ( "SETUP: could not append to the revocation list" ); return 2; }
                if ( oServer.ReloadRevocationList ( ) != p2pcng::IdOk )
                { Log ( "SETUP: ReloadRevocationList failed on the running hub" ); return 2; }
                Log ( "revocation list reloaded - no restart" );

                bool b3 = RunPhase ( sOldKey, sCliAcl, kPayOld3, g_hPhase3, nPort,
                                     10000, &bSetup );
                if ( bSetup ) { Log ( "SETUP: phase 3 client failed" ); return 2; }

                // ---- Phase 4: liveness, the NEW key --------------------
                Log ( "--- phase 4: client presents the NEW key again (liveness) ---" );
                bool b4 = RunPhase ( sNewKey, sCliAcl, kPayNew4, g_hPhase4, nPort,
                                     15000, &bSetup );
                if ( bSetup ) { Log ( "SETUP: phase 4 client failed" ); return 2; }

                if ( b3 )
                {
                    std::printf (
                      "\nRESULT: FAIL - A REVOKED KEY STILL LOGS IN.\n"
                      "  The old key was appended to the revocation list and the\n"
                      "  server reloaded it, and the peer holding that key was still\n"
                      "  accepted. A withdrawn key that keeps working means there is\n"
                      "  no way to respond to a compromise short of editing every\n"
                      "  allow-list in the deployment and restarting.\n" );
                    nExit = 1;
                }
                else if ( !b4 )
                {
                    std::printf (
                      "\nRESULT: INCONCLUSIVE - the revoked key was refused, but so\n"
                      "  was the key that should still work. The server may simply\n"
                      "  have stopped accepting anything, in which case phase 3\n"
                      "  proves nothing: a dead server and a working revocation are\n"
                      "  both silence. Check that revocation refuses the revoked\n"
                      "  POINT rather than the address it was listed under.\n" );
                    nExit = 3;
                }
                else
                {
                    std::printf (
                      "\nRESULT: PASS - rotation and revocation both hold.\n"
                      "  Two keys listed for one peer: both accepted (phases 1, 2).\n"
                      "  One of them revoked on the running server: refused, with\n"
                      "  the allow-list still naming it (phase 3).\n"
                      "  The other still accepted afterwards, so the refusal was\n"
                      "  the revocation and not a dead hub (phase 4).\n" );
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
    if ( g_hPhase1 ) { CloseHandle ( g_hPhase1 ); g_hPhase1 = NULL; }
    if ( g_hPhase2 ) { CloseHandle ( g_hPhase2 ); g_hPhase2 = NULL; }
    if ( g_hPhase3 ) { CloseHandle ( g_hPhase3 ); g_hPhase3 = NULL; }
    if ( g_hPhase4 ) { CloseHandle ( g_hPhase4 ); g_hPhase4 = NULL; }
    WSACleanup ( );

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
