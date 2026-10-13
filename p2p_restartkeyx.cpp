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
// p2p_restartkeyx.cpp - does a CLIENT connection that Targetcore restarts by
// itself (m_uAutoRestart) run the session key agreement again?
//
// BACKGROUND - finding F-L7-2, found 2026-10-14 by P2PeerLan's lan_join_test
// (a LAN root's node restarted under a node that had been linked to it). The
// per-connection agreement state in P2PeerCon - m_bKeyXDone, the ECDH pair in
// m_pKeyX, the binding, the auth nonce - was initialised in the constructor and
// never again. P2PeerTarget::On_ConClose / On_ConShutdown restart a CLIENT
// connection by reusing the SAME object (P2PeerCon::Restart, then P2P_Startup
// off the restart timer), and P2Peerio::Reset() had already dropped the
// session cypher with the socket. So the restarted connection:
//
//   * found m_bKeyXDone true, and Login() sent the login at once - no
//     agreement, in clear, with a stale binding in its signature;
//   * could not have started one anyway: KeyXBegin() returns early while
//     m_pKeyX is set, and nothing freed it after the derive.
//
// A server that requires authentication answered every attempt with "Login
// arrived with no session key agreement on a hub that requires
// authentication" and dropped it - every m_uAutoRestart milliseconds, forever.
// Worse for an application: ConExists() stays true while that doomed restart
// is pending, so "redial if there is no link" code never dials either.
//
// WHAT IT DOES - one client hub, two server hubs in turn on one port.
//
//   Phase 1 (POSITIVE CONTROL): client and server both RequireAuth(true). The
//   client logs in and posts "round-1"; the server MUST accept and receive it.
//
//   Phase 2 (THE RESTART): the server hub is closed - the client's connection
//   drops - and a NEW server hub (same address, key, allow-list and port) is
//   started. The client is left alone: its connection object restarts itself
//   (m_uAutoRestart = 500 ms here, 20 s by default) until the port answers.
//   The new server MUST accept a login from it and receive "round-2".
//
// The verdict is the second server's On_ConLogin and the payload, not the
// client's view: the refusal this test exists for happens at the server.
//
// VERDICT = process EXIT CODE:
//   0  PASS   the restarted connection logged in again and delivered
//   1  FAIL   the second server never accepted the restarted connection
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

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kServerAddr = L"Restart.Server";
static const P2PaddrSTR kClientAddr = L"Restart.Client";
static const P2PaddrSTR kDomain     = L"Restart.*";

static HANDLE g_hLogin1 = NULL;   // server 1 accepted a login
static HANDLE g_hRound1 = NULL;   // server 1 received round-1
static HANDLE g_hLogin2 = NULL;   // server 2 accepted a login - the verdict
static HANDLE g_hRound2 = NULL;   // server 2 received round-2

static std::atomic<int> g_nServer ( 0 );   // which server hub is up
static std::atomic<int> g_nAcks   ( 0 );   // client logins acknowledged

static void Log ( const char *msg )
{
    std::printf ( "[restartkeyx] %s\n", msg );
    std::fflush ( stdout );
}

// The payload is copied out: P2PeerMsg::Data() is not aligned for wchar_t
// (F-S5-3; see p2p_authchannel.cpp).
static std::string BodyA ( P2PeerMsg *pMsg )
{
    std::string s;
    if ( !pMsg || !pMsg->Data ( ) ) return s;
    const size_t cb = (size_t)pMsg->DataSize ( );
    std::vector<wchar_t> w ( cb / sizeof(wchar_t) + 1, L'\0' );
    std::memcpy ( w.data ( ), pMsg->Data ( ), ( w.size ( ) - 1 ) * sizeof(wchar_t) );
    for ( const wchar_t *p = w.data ( ); *p; ++p )
        s.push_back ( *p < 0x80 ? (char)*p : '?' );
    return s;
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
    s += "p2p_restartkeyx_"; s += pszLeaf; s += "_"; s += szPid; s += ".tmp";
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
class RestartHub : public P2PeerHub
{
public:
    RestartHub ( P2PaddrSTR strAddr, bool bServer )
        : P2PeerHub ( strAddr ), m_bServer ( bServer )
    { m_strSelf = strAddr; }
    virtual ~RestartHub ( ) {}

protected:
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_bServer && pMsg )
        {
            const std::string sBody = BodyA ( pMsg );
            std::printf ( "[restartkeyx] SERVER %d received '%s'\n",
                          g_nServer.load ( ), sBody.c_str ( ) );
            std::fflush ( stdout );
            if      ( sBody == "round-1" && g_nServer == 1 ) SetEvent ( g_hRound1 );
            else if ( sBody == "round-2" && g_nServer == 2 ) SetEvent ( g_hRound2 );
        }
        return msgHANDLED;
    }

    virtual conRESULT On_ConLogin ( P2PeerCon *pCon, P2PaddrSTR strThatP2Paddr,
                                    const void *pvLoginMsg, P2Psize_t iSize ) override
    {
        if ( m_bServer )
        {
            std::printf ( "[restartkeyx] SERVER %d ACCEPTED a login (keyed: %s)\n",
                          g_nServer.load ( ), pCon->IsKeyXDone ( ) ? "yes" : "NO" );
            std::fflush ( stdout );
            if      ( g_nServer == 1 ) SetEvent ( g_hLogin1 );
            else if ( g_nServer == 2 ) SetEvent ( g_hLogin2 );
        }
        return P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr, pvLoginMsg, iSize );
    }

    // Every acknowledged login posts the next round - the restarted connection
    // has no other way to show it is back.
    virtual conRESULT On_ConLoginAck ( P2PeerCon  *pCon,
                                       P2PaddrSTR  strThisP2Paddr,
                                       P2PaddrSTR  strThatP2Paddr,
                                       const void *pvLoginAck,
                                       P2Psize_t   iSize ) override
    {
        conRESULT result = P2PeerHub::On_ConLoginAck ( pCon, strThisP2Paddr,
                                                       strThatP2Paddr,
                                                       pvLoginAck, iSize );
        if ( !m_bServer )
        {
            const int n = ++g_nAcks;
            std::wstring w = L"round-" + std::to_wstring ( n );
            PostP2PeerMsg ( new P2PeerMsg32 ( m_strSelf.GetString ( ), kServerAddr,
                                              P2Pmsg_BCast, w.c_str ( ),
                                              (P2Psize_t)( ( w.size ( ) + 1 ) * sizeof(wchar_t) ) ) );
            std::printf ( "[restartkeyx] client logged in (#%d) and posted 'round-%d'\n", n, n );
            std::fflush ( stdout );
        }
        return result;
    }

private:
    bool    m_bServer;
    CString m_strSelf;
};

// One server hub: auth on, the client's key listed, a service on nPort.
static bool StartServer ( RestartHub &oServer, HANDLE &hThread,
                          const std::string &sKey, const std::string &sAcl, short nPort )
{
    if ( oServer.SetIdentity  ( sKey.c_str ( ) ) != p2pcng::IdOk ||
         oServer.SetAllowList ( sAcl.c_str ( ) ) != p2pcng::IdOk )
        return false;
    oServer.RequireAuth ( true );
    oServer.RequireRevocation ( false );     // not about revocation; see p2p_authchannel
    hThread = oServer.SpawnHub ( );
    if ( !hThread ) return false;
    P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
    if ( !pSvc ) return false;
    oServer.PostP2PeerCon ( pSvc );
    return true;
}

static void StopServer ( RestartHub &oServer, HANDLE hThread )
{
    oServer.CloseHub ( );
    WaitForSingleObject ( hThread, 5000 );
    CloseHandle ( hThread );
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7837;

    std::printf ( "=== p2p_restartkeyx - does an auto-restarted connection agree keys again? ===\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::printf ( "Asserting: a client connection restarted by Targetcore itself logs in\n"
                  "           again to a server that requires authentication.\n\n" );
    std::fflush ( stdout );

    g_hLogin1 = CreateEvent ( NULL, TRUE, FALSE, NULL );
    g_hRound1 = CreateEvent ( NULL, TRUE, FALSE, NULL );
    g_hLogin2 = CreateEvent ( NULL, TRUE, FALSE, NULL );
    g_hRound2 = CreateEvent ( NULL, TRUE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    const std::string sSrvKey = TempPath ( "srvkey" );
    const std::string sCliKey = TempPath ( "clikey" );
    const std::string sSrvAcl = TempPath ( "srvacl" );
    const std::string sCliAcl = TempPath ( "cliacl" );

    unsigned char pubSrv[p2pcng::kEcdsaPubLen];
    unsigned char pubCli[p2pcng::kEcdsaPubLen];
    if ( !MakeIdentity ( sSrvKey, pubSrv ) || !MakeIdentity ( sCliKey, pubCli ) ||
         p2pcng::AppendAllowList ( sSrvAcl.c_str ( ), "Restart.Client", pubCli ) != p2pcng::IdOk ||
         p2pcng::AppendAllowList ( sCliAcl.c_str ( ), "Restart.Server", pubSrv ) != p2pcng::IdOk )
    { Log ( "SETUP: provisioning failed" ); ScrubTempFiles ( ); return 2; }

    int nExit = 2;
    {
        // ---- the client, which lives through both servers ------------------
        RestartHub oClient ( kClientAddr, false );
        if ( oClient.SetIdentity  ( sCliKey.c_str ( ) ) != p2pcng::IdOk ||
             oClient.SetAllowList ( sCliAcl.c_str ( ) ) != p2pcng::IdOk )
        { Log ( "SETUP: client auth configuration failed" ); ScrubTempFiles ( ); return 2; }
        oClient.RequireAuth ( true );
        oClient.RequireRevocation ( false );

        // ---- phase 1 --------------------------------------------------------
        RestartHub *pServer1 = new RestartHub ( kServerAddr, true );
        HANDLE hServer1 = NULL;
        g_nServer = 1;
        if ( !StartServer ( *pServer1, hServer1, sSrvKey, sSrvAcl, nPort ) )
        { Log ( "SETUP: server 1 failed" ); ScrubTempFiles ( ); return 2; }
        Sleep ( 300 );

        HANDLE hClient = oClient.SpawnHub ( );
        P2PeerConWsa *pCon = P2PeerConWsa::ClientFactory ( kServerAddr, L"127.0.0.1", nPort );
        if ( !hClient || !pCon ) { Log ( "SETUP: client failed" ); ScrubTempFiles ( ); return 2; }
        pCon->m_uAutoRestart = 500;          // Targetcore's own restart, sooner than 20 s
        oClient.PostP2PeerCon ( pCon );

        Log ( "--- phase 1: login to server 1 (positive control) ---" );
        const bool b1 = WaitForSingleObject ( g_hRound1, 15000 ) == WAIT_OBJECT_0 &&
                        WaitForSingleObject ( g_hLogin1, 0 )     == WAIT_OBJECT_0;
        if ( !b1 )
        {
            std::printf ( "\nRESULT: INCONCLUSIVE - the first login never got through, so the\n"
                          "  transport is broken and the restart proves nothing.\n" );
            nExit = 3;
        }
        else
        {
            // ---- phase 2 ----------------------------------------------------
            Log ( "--- phase 2: server 1 goes away; server 2 starts on the same port ---" );
            g_nServer = 0;
            StopServer ( *pServer1, hServer1 );
            delete pServer1;
            Sleep ( 1500 );                  // at least one refused restart in between

            RestartHub oServer2 ( kServerAddr, true );
            HANDLE hServer2 = NULL;
            g_nServer = 2;
            if ( !StartServer ( oServer2, hServer2, sSrvKey, sSrvAcl, nPort ) )
            { Log ( "SETUP: server 2 failed" ); ScrubTempFiles ( ); return 2; }

            const bool bRound2 = WaitForSingleObject ( g_hRound2, 20000 ) == WAIT_OBJECT_0;
            const bool bLogin2 = WaitForSingleObject ( g_hLogin2, 0 )     == WAIT_OBJECT_0;
            std::printf ( "[restartkeyx] phase 2: login accepted = %s, round-2 delivered = %s, "
                          "client logins acknowledged = %d\n",
                          bLogin2 ? "yes" : "NO", bRound2 ? "yes" : "NO", g_nAcks.load ( ) );
            std::fflush ( stdout );

            if ( bLogin2 && bRound2 )
            {
                std::printf ( "\nRESULT: PASS - the connection Targetcore restarted ran the key\n"
                              "  agreement again, logged in to the new server and delivered.\n" );
                nExit = 0;
            }
            else
            {
                std::printf ( "\nRESULT: FAIL - the restarted connection never logged in again.\n"
                              "  If the server log says \"Login arrived with no session key\n"
                              "  agreement\", the connection kept its old agreement state across\n"
                              "  P2PeerCon::Restart (F-L7-2): m_bKeyXDone still true, m_pKeyX\n"
                              "  still set, and the cypher already gone with the socket.\n" );
                nExit = 1;
            }
            StopServer ( oServer2, hServer2 );
        }

        oClient.CloseHub ( );
        WaitForSingleObject ( hClient, 5000 );
        CloseHandle ( hClient );
    }

    ScrubTempFiles ( );
    WSACleanup ( );
    CleanupP2Pmsg ( );
    CloseHandle ( g_hLogin1 );
    CloseHandle ( g_hRound1 );
    CloseHandle ( g_hLogin2 );
    CloseHandle ( g_hRound2 );
    return nExit;
}
