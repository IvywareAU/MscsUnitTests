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
// p2p_authchannel.cpp - SECURITY GATE TEST: does a hub that requires
// authentication also require the CHANNEL it authenticated on?
//
// BACKGROUND - the gap this closes, and how it was found. Not by fuzzing and
// not by a crash: by writing THREAT_MODEL.md (ProductionPlan.md Stage 6 step
// 17) and checking, one protection at a time, which adversary each one
// answers and where it is enforced. Two conditions in P2PeerCon turned out to
// be independent when the documentation describes them as one:
//
//   * KeyXWanted()  == "does my hub require authentication"  - decides whether
//     this connection runs the ECDH key agreement, and therefore whether it
//     has a session cypher and a channel binding at all.
//   * CanAuthSign() == "do I hold an identity key"           - decides whether
//     this connection SIGNS its login.
//
// SECURITY.md calls encryption and authentication "one switch on purpose",
// and on the INITIATING side they are. On the VERIFYING side they were not.
// AuthGateInbound() verified the signature and passed
// m_bKeyXBound ? m_KeyXBind : 0 as the channel binding - so a login signed
// with a NULL binding, by a peer that never ran the key agreement, produced
// the same transcript at both ends and verified.
//
// A hub with RequireAuth(false) that nevertheless holds an identity key is not
// an exotic configuration - it is the ordinary state of a peer provisioned for
// somewhere else in the tree. It signs, it does not exchange keys, and before
// this gate an auth-requiring server accepted it: an AUTHENTICATED connection
// carrying CLEARTEXT, which the server reported as a successful login and
// which no accessor on either object would have contradicted.
//
// Two things were lost, not one. The obvious one is confidentiality - every
// message on that session is readable by anyone on the path. The other is the
// reason the login block kVersion moved from 1 to 2 in the first place: v2
// exists to bind the proof to the connection it was made on, and a null
// binding names no connection, so for that session the binding is not in the
// transcript at all.
//
// WHAT IT DOES - three phases against ONE long-lived server that requires
// authentication. The client uses the SAME key and the SAME address in every
// phase. The only thing that changes is one call.
//
//   Phase 1 (POSITIVE CONTROL): client with RequireAuth(true). The agreement
//   runs, the login is signed over the channel binding, the server MUST accept
//   the login and the message MUST arrive. Without this every later refusal is
//   indistinguishable from a broken transport.
//
//   Phase 2 (THE GATE): the same client, same key, with RequireAuth(false).
//   It still signs - it holds the key - but it runs no agreement, so the
//   signature covers a null binding and the wire is plaintext. The server MUST
//   NOT accept the login. It is the whole point of the test.
//
//   Phase 3 (LIVENESS): phase 1 again, different payload. MUST arrive. A
//   server that has fallen over also refuses everything, and without this
//   "refused" and "dead" are both silence.
//
// WHAT IT MEASURES, AND THE TRAP IT FELL INTO FIRST. The verdict is taken from
// the SERVER accepting a login (On_ConLogin), not from a payload arriving.
// That distinction is not fussiness - the first version of this test took
// delivery as the verdict and PASSED against the tree that had the defect,
// which is the worst outcome a gate can have. What actually happened in phase
// 2 was this, from the run log:
//
//   [authchannel] SERVER accepted a login claiming 'AuthChan.Client'
//   [ERROR] P2PeerTarget::On_ConLoginAck ... Remote MSG_P2PeerLoginAck
//           contains data / ADVICE: Implement custom handler
//
// The server took the unbound cleartext login. The payload never arrived only
// because the CLIENT then choked on the server's signed acknowledgement: with
// RequireAuth(false) its own AuthGateInbound returns before stripping, so the
// 67-byte ack block reached the stock On_ConLoginAck, which refuses any ack
// carrying data. That refusal is incidental and it is not a security decision.
// An application with the custom handler that error message advises writing
// would not have refused, and the cleartext authenticated session would have
// run. Measuring delivery therefore measured the client's stock handler; only
// measuring acceptance measures the gate.
//
// NOT WILL_FAIL, and it never was: the gate asserts the behaviour the fix
// gives, and it was RED before the fix and green after. The commit that adds
// it adds the refusal in P2PeerCon::AuthGateInbound in the same breath.
//
// VERDICT = process EXIT CODE:
//   0  PASS   1 and 3 delivered, 2 refused
//   1  FAIL   the unbound cleartext login was accepted, or a good one refused
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
static const P2PaddrSTR kServerAddr = L"AuthChan.Server";
static const P2PaddrSTR kClientAddr = L"AuthChan.Client";   // all three clients
static const P2PaddrSTR kDomain     = L"AuthChan.*";

// Every client claims the same address and holds the same key, so neither the
// source nor the identity can tell the phases apart. The payload does.
static const wchar_t *kPayBound1   = L"phase1-bound";
static const wchar_t *kPayUnbound2 = L"phase2-unbound-cleartext";
static const wchar_t *kPayBound3   = L"phase3-liveness";

// Payload arrival, per phase.
static HANDLE g_hPhase1 = NULL;
static HANDLE g_hPhase2 = NULL;   // must stay unsignalled
static HANDLE g_hPhase3 = NULL;

// LOGIN ACCEPTANCE, per phase - the verdict. Set from the server's
// On_ConLogin, which is reached only once AuthGateInbound has let the login
// through. See the header for why delivery is the wrong thing to measure.
static HANDLE g_hLogin1 = NULL;
static HANDLE g_hLogin2 = NULL;   // must stay unsignalled
static HANDLE g_hLogin3 = NULL;

// Which phase is running. Written by main between phases, when no client hub
// exists; read by the server pump thread. There is no concurrent write.
static int g_nPhase = 0;

static void Log ( const char *msg )
{
    std::printf ( "[authchannel] %s\n", msg );
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
//  behaviour; on Linux, where wchar_t wants 4-byte alignment, UBSan reports it
//  at the dereference.  Targetcore's finding F-S5-3.
//    Copying the bytes out into storage the caller aligned is the fix.  See
//  P3PmsgData::c_vBlobCopy() for the same thing offered as an accessor.
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
    s += "p2p_authchannel_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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

// =========================================================================
class ChanHub : public P2PeerHub
{
public:
    ChanHub ( P2PaddrSTR strAddr, bool bServer, const wchar_t *pszPayload )
        : P2PeerHub ( strAddr ), m_bServer ( bServer )
        , m_bSent ( false ), m_pszPayload ( pszPayload )
    { m_strSelf = strAddr; }
    virtual ~ChanHub ( ) {}

protected:
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_bServer && pMsg )
        {
            const std::wstring wBody = BodyW ( pMsg );   // copied out, aligned
            std::string sSrc  = N ( pMsg->GetSource ( ) );
            std::string sBody = pMsg->Data ( ) ? N ( wBody.c_str ( ) )
                                               : std::string ( "<null>" );
            std::printf ( "[authchannel] SERVER handler ran; source='%s' body='%s'\n",
                          sSrc.c_str ( ), sBody.c_str ( ) );
            std::fflush ( stdout );

            if      ( sBody == N ( kPayBound1   ) ) { if ( g_hPhase1 ) SetEvent ( g_hPhase1 ); }
            else if ( sBody == N ( kPayUnbound2 ) ) { if ( g_hPhase2 ) SetEvent ( g_hPhase2 ); }
            else if ( sBody == N ( kPayBound3   ) ) { if ( g_hPhase3 ) SetEvent ( g_hPhase3 ); }
        }
        return msgHANDLED;
    }

    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        if ( m_bServer )
        {
            std::printf ( "[authchannel] SERVER ACCEPTED a login claiming '%s' "
                          "(phase %d)\n",
                          N ( strThatP2Paddr ).c_str ( ), g_nPhase );
            std::fflush ( stdout );

            // The verdict. Reached only after AuthGateInbound has passed the
            // login, so this is the gate's answer and nothing downstream of it.
            if      ( g_nPhase == 1 ) { if ( g_hLogin1 ) SetEvent ( g_hLogin1 ); }
            else if ( g_nPhase == 2 ) { if ( g_hLogin2 ) SetEvent ( g_hLogin2 ); }
            else if ( g_nPhase == 3 ) { if ( g_hLogin3 ) SetEvent ( g_hLogin3 ); }
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
            std::printf ( "[authchannel] client logged in and posted '%s'\n",
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
// One phase. bRequireAuth is the ONLY thing that differs between phase 1 and
// phase 2 - same key file, same allow-list, same address, same server.
//
// With it false the client still signs, because SetIdentity() gave it a key
// and CanAuthSign() is what drives the signature. What it does not do is run
// the key agreement, so there is no session cypher and no channel binding to
// name. That combination is the finding.
// -------------------------------------------------------------------------
static bool RunPhase ( int nPhase,
                       const std::string &sKeyFile, const std::string &sCliAcl,
                       bool bRequireAuth, const wchar_t *pszPayload,
                       HANDLE hEvent, HANDLE hLoginEvent,
                       short nPort, DWORD dwWaitMs,
                       bool *pbSetupFailed, bool *pbLoginAccepted )
{
    *pbSetupFailed    = false;
    *pbLoginAccepted  = false;
    g_nPhase          = nPhase;

    ChanHub oClient ( kClientAddr, false, pszPayload );
    if ( oClient.SetIdentity  ( sKeyFile.c_str ( ) ) != p2pcng::IdOk ||
         oClient.SetAllowList ( sCliAcl .c_str ( ) ) != p2pcng::IdOk )
    { *pbSetupFailed = true; return false; }
    oClient.RequireAuth ( bRequireAuth );
    //  RequireRevocation(false) since 2026-08-21 (Stage 3 step 19). This hub
    //  takes RequireAuth as a PARAMETER, which is the point of the phase - so
    //  it needs a revocation position whichever way that parameter goes, and
    //  this test is not about revocation.
    oClient.RequireRevocation ( false );

    HANDLE hThread = oClient.SpawnHub ( );
    P2PeerConWsa *pCon =
        P2PeerConWsa::ClientFactory ( kServerAddr, L"127.0.0.1", nPort );
    if ( !hThread || !pCon ) { *pbSetupFailed = true; return false; }
    oClient.PostP2PeerCon ( pCon );

    bool bArrived = ( WaitForSingleObject ( hEvent, dwWaitMs ) == WAIT_OBJECT_0 );

    // Read acceptance AFTER the payload wait, not before: in the phases that
    // are meant to succeed the login necessarily precedes the payload, and in
    // the phase that is meant to fail the full wait has to elapse before a
    // login that never came can be called absent.
    *pbLoginAccepted =
        ( WaitForSingleObject ( hLoginEvent, 0 ) == WAIT_OBJECT_0 );

    oClient.CloseHub ( );
    WaitForSingleObject ( hThread, 3000 );
    CloseHandle ( hThread );
    Sleep ( 300 );                       // let the server drop its side
    return bArrived;
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7836;

    std::printf ( "=== p2p_authchannel - is the proof bound to a channel that exists? ===\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::printf ( "Asserting: a hub that requires authentication refuses a login\n"
                  "           that arrives on a connection with no key agreement,\n"
                  "           however well it is signed.\n\n" );
    std::fflush ( stdout );

    // Manual reset: the acceptance events are polled with a zero timeout after
    // the payload wait, so they must stay signalled once set.
    g_hPhase1 = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hPhase2 = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hPhase3 = CreateEvent ( NULL, FALSE, FALSE, NULL );
    g_hLogin1 = CreateEvent ( NULL, TRUE,  FALSE, NULL );
    g_hLogin2 = CreateEvent ( NULL, TRUE,  FALSE, NULL );
    g_hLogin3 = CreateEvent ( NULL, TRUE,  FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    // ---- Provisioning -----------------------------------------------------
    const std::string sSrvKey = TempPath ( "srvkey" );
    const std::string sCliKey = TempPath ( "clikey" );
    const std::string sSrvAcl = TempPath ( "srvacl" );
    const std::string sCliAcl = TempPath ( "cliacl" );

    unsigned char pubSrv[p2pcng::kEcdsaPubLen];
    unsigned char pubCli[p2pcng::kEcdsaPubLen];
    if ( !MakeIdentity ( sSrvKey, pubSrv ) ||
         !MakeIdentity ( sCliKey, pubCli ) )
    { Log ( "SETUP: identity generation failed" ); ScrubTempFiles ( ); return 2; }

    if ( p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "AuthChan.Client", pubCli ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sCliAcl.c_str ( ), "AuthChan.Server", pubSrv ) != p2pcng::IdOk )
    { Log ( "SETUP: allow-list provisioning failed" ); ScrubTempFiles ( ); return 2; }

    char szFp[p2pcng::kIdFingerprintLen];
    if ( p2pcng::Fingerprint ( pubCli, szFp ) )
        std::printf ( "[authchannel] AuthChan.Client key = %s (LISTED, and the same\n"
                      "              key in all three phases)\n", szFp );
    std::fflush ( stdout );

    int nExit = 2;
    {
        ChanHub oServer ( kServerAddr, true, 0 );
        if ( oServer.SetIdentity  ( sSrvKey.c_str ( ) ) != p2pcng::IdOk ||
             oServer.SetAllowList ( sSrvAcl.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: server auth configuration failed" ); ScrubTempFiles ( ); return 2; }
        oServer.RequireAuth ( true );
        //  RequireRevocation(false) since 2026-08-21 (Stage 3 step 19): a hub
        //  that requires auth must now hold a POSITION on revocation, and this
        //  test is not about revocation. Saying so is the documented migration
        //  and it is one line. It does NOT turn revocation off - a list named
        //  anyway is still loaded, still enforced and still fails closed.
        oServer.RequireRevocation ( false );

        HANDLE hServerThread = oServer.SpawnHub ( );
        if ( !hServerThread ) { Log ( "SETUP: server SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        oServer.PostP2PeerCon ( pSvc );
        Log ( "server listening, RequireAuth(true), client key on its allow-list" );
        Sleep ( 500 );

        bool bSetup = false;
        bool bLogin1 = false, bLogin2 = false, bLogin3 = false;

        // ---- Phase 1: positive control ---------------------------------
        Log ( "--- phase 1: client RequireAuth(true) - agreement runs (must arrive) ---" );
        bool b1 = RunPhase ( 1, sCliKey, sCliAcl, true, kPayBound1, g_hPhase1,
                             g_hLogin1, nPort, 15000, &bSetup, &bLogin1 );
        if ( bSetup ) { Log ( "SETUP: phase 1 client failed" ); return 2; }

        if ( !b1 || !bLogin1 )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the legitimate peer never got through, so\n"
              "  the transport is broken and phase 2 proves nothing. This is NOT a\n"
              "  pass. Check wsa_mesh and p2p_authpsk first.\n" );
            nExit = 3;
        }
        else
        {
            Log ( "positive control OK - bound, sealed login accepted" );

            // ---- Phase 2: the gate ------------------------------------
            Log ( "--- phase 2: SAME key, RequireAuth(false) - signed but unbound "
                  "and in clear (must NOT arrive) ---" );
            bool b2 = RunPhase ( 2, sCliKey, sCliAcl, false, kPayUnbound2, g_hPhase2,
                                 g_hLogin2, nPort, 10000, &bSetup, &bLogin2 );
            if ( bSetup ) { Log ( "SETUP: phase 2 client failed" ); return 2; }
            std::printf ( "[authchannel] phase 2: login accepted = %s, "
                          "payload delivered = %s\n",
                          bLogin2 ? "YES" : "no", b2 ? "YES" : "no" );
            std::fflush ( stdout );

            // ---- Phase 3: liveness -------------------------------------
            Log ( "--- phase 3: client RequireAuth(true) again (liveness) ---" );
            bool b3 = RunPhase ( 3, sCliKey, sCliAcl, true, kPayBound3, g_hPhase3,
                                 g_hLogin3, nPort, 15000, &bSetup, &bLogin3 );
            if ( bSetup ) { Log ( "SETUP: phase 3 client failed" ); return 2; }

            if ( bLogin2 || b2 )
            {
                std::printf (
                  "\nRESULT: FAIL - AN AUTHENTICATED CLEARTEXT SESSION WAS ACCEPTED.\n"
                  "  The peer signed its login with a key the server trusts, and the\n"
                  "  server took it - but that peer ran no key agreement, so there is\n"
                  "  no session cypher on the connection and the signature covers a\n"
                  "  NULL channel binding. Everything that follows is readable by\n"
                  "  anyone on the path, on a hub whose operator set RequireAuth(true)\n"
                  "  and was told that encryption and authentication are one switch.\n"
                  "  The binding is also absent from the transcript, which is what\n"
                  "  login kVersion 2 exists to put there.\n"
                  "  Fix: AuthGateInbound() must refuse when KeyXWanted() is true and\n"
                  "  the agreement has not completed.\n"
                  "  NOTE: read the two flags above. If the login was accepted and\n"
                  "  the payload was not, the gate is still OPEN - what stopped the\n"
                  "  payload was the stock On_ConLoginAck refusing an ack it did not\n"
                  "  expect to carry data, which any application with a custom\n"
                  "  handler removes.\n" );
                nExit = 1;
            }
            else if ( !b3 || !bLogin3 )
            {
                std::printf (
                  "\nRESULT: FAIL - the liveness control never arrived. Phase 2 was\n"
                  "  refused, but so was a login that must be accepted, so the\n"
                  "  refusal cannot be attributed to the channel check.\n" );
                nExit = 1;
            }
            else
            {
                std::printf (
                  "\nRESULT: PASS - the unbound cleartext login was REFUSED AT THE\n"
                  "  GATE (the server never reached On_ConLogin for it), and a bound\n"
                  "  one before and after it was accepted. Authentication and the\n"
                  "  channel are one switch at the VERIFYING end too.\n" );
                nExit = 0;
            }
        }

        oServer.CloseHub ( );
        WaitForSingleObject ( hServerThread, 5000 );
        CloseHandle ( hServerThread );
    }

    ScrubTempFiles ( );
    WSACleanup ( );
    CleanupP2Pmsg ( );
    if ( g_hPhase1 ) CloseHandle ( g_hPhase1 );
    if ( g_hPhase2 ) CloseHandle ( g_hPhase2 );
    if ( g_hPhase3 ) CloseHandle ( g_hPhase3 );
    if ( g_hLogin1 ) CloseHandle ( g_hLogin1 );
    if ( g_hLogin2 ) CloseHandle ( g_hLogin2 );
    if ( g_hLogin3 ) CloseHandle ( g_hLogin3 );
    return nExit;
}
