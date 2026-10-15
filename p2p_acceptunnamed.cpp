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
// p2p_acceptunnamed - does a listener with ConState_AcceptUnnamed hand its
// accepted children an EMPTY peer address, before they are published?
//
// WHY: P2PeerCon::AcceptSpawn copies the listener's peer address into every
// accepted child, and OnAccept(addr) refuses to replace an address already
// set. A service that names its children afterwards - _OldExamples\AKAserva,
// whose browsers have no P2P identity and become Webserver.<n> - therefore
// dropped every connection, and its port cleared the address in its own
// AcceptSpawn override AFTER the base had published the child to the hub list,
// outside ThatAddrLock (AKAserva PORTING.md, 2026-10-14). Targetcore 3.4.3 adds
// the service bit so the base names the child blank before it is published.
//
// HOW: one hub, one WSA service on the wildcard domain Una.*, one raw TCP
// client that never speaks. The hub's connections are walked from this thread
// with P2PretainedCons and the accepted one (GetMode() == P2PeerCon_Accept)
// is read through CopyP2Paddress, the any-thread reader.
//
//   phase 1  POSITIVE CONTROL, no bit: the child carries the listener's
//            address. If it does not, the walk is not finding the child and
//            phase 2's empty address would prove nothing.
//   phase 2  the bit: the child's address is empty, the child does not carry
//            the bit itself, and the listener's own address is untouched.
//
// Exit codes: 0 pass, 1 fail, 2 setup, 3 inconclusive (the control failed).

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
static const P2PaddrSTR kServerAddr = L"Una.Server";
static const P2PaddrSTR kDomain     = L"Una.*";

static void Log ( const char *msg )
{
    std::printf ( "[acceptunnamed] %s\n", msg );
    std::fflush ( stdout );
}

static SOCKET RawConnect ( short nPort )
{
    SOCKET s = socket ( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    if ( s == INVALID_SOCKET ) return INVALID_SOCKET;

    sockaddr_in oAddr;
    std::memset ( &oAddr, 0, sizeof(oAddr) );
    oAddr.sin_family      = AF_INET;
    oAddr.sin_port        = htons ( (u_short)nPort );
    oAddr.sin_addr.s_addr = inet_addr ( "127.0.0.1" );

    if ( connect ( s, (sockaddr *)&oAddr, sizeof(oAddr) ) == SOCKET_ERROR )
    { closesocket ( s ); return INVALID_SOCKET; }

    return s;
}

class UnaHub : public P2PeerHub
{
public:
    UnaHub ( P2PaddrSTR strAddr ) : P2PeerHub ( strAddr ) { }
    virtual ~UnaHub ( ) { }
};

//  What one phase saw
struct Seen
{
    int          nAccepted     = 0;      // children found in the walk
    bool         bChildNull    = false;  // the (first) child's address is empty
    bool         bChildHasBit  = false;  // the child carries ConState_AcceptUnnamed
    std::wstring strChild;               // the child's address, as text
    std::wstring strService;             // the listener's address, after the accept
};

static std::wstring Text ( const P2Paddr& a )
{
    if ( a.IsNull ( ) ) return std::wstring ( );
    LPCTADDR p = a;
    return p ? std::wstring ( p ) : std::wstring ( );
}

//  One hub, one service, one raw client; returns 2 on a setup failure
static int RunPhase ( short nPort, bool bUnnamed, Seen& out )
{
    int nRet = 0;
    {
        UnaHub oServer ( kServerAddr );
        //  RequireAuth(false): the raw client never logs in, and this measures
        //  what AcceptSpawn wrote, which happens before any login could
        oServer.RequireAuth ( false );
        HANDLE hThread = oServer.SpawnHub ( );
        if ( !hThread ) { Log ( "SETUP: SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        pSvc -> SetLoginDeadline ( 0 );          // nothing may drop the child first
        if ( bUnnamed )
          pSvc -> SetState ( ConState_AcceptUnnamed, 0 );
        oServer.PostP2PeerCon ( pSvc );
        Sleep ( 500 );

        SOCKET s = RawConnect ( nPort );
        if ( s == INVALID_SOCKET )
        {
            Log ( "SETUP: the raw client could not connect" );
            nRet = 2;
        }
        else
        {
            //  The accept settles on the hub's pump; give it time, then walk
            for ( int i = 0; i < 20 && out.nAccepted == 0; ++i )
            {
                Sleep ( 100 );
                P2PretainedCons oCons ( oServer.GetHubID ( ) );
                for ( P2PeerCon *pCon : oCons.v )
                {
                    if ( pCon -> GetMode ( ) == P2PeerCon_Accept )
                    {
                        if ( out.nAccepted++ == 0 )
                        {
                            P2Paddr a = pCon -> CopyP2Paddress ( );
                            out.bChildNull   = a.IsNull ( );
                            out.strChild     = Text ( a );
                            out.bChildHasBit = pCon -> HasState ( ConState_AcceptUnnamed );
                        }
                    }
                    else if ( pCon == pSvc )
                      out.strService = Text ( pCon -> CopyP2Paddress ( ) );
                }
            }
            closesocket ( s );
            Sleep ( 300 );
        }

        oServer.CloseHub ( );
        WaitForSingleObject ( hThread, 3000 );
        CloseHandle ( hThread );
    }
    return nRet;
}

int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7812;

    std::printf ( "=== p2p_acceptunnamed - ConState_AcceptUnnamed on a WSA service ===\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::printf ( "Asserting: with the bit, an accepted child starts with an empty peer\n"
                  "           address (and without it, a copy of the listener's).\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    int nExit = 0;

    // ---- phase 1: the positive control --------------------------------------
    Log ( "--- phase 1: no bit, the child must carry the listener's address ---" );
    Seen oCtl;
    if ( RunPhase ( nPort, false, oCtl ) != 0 ) { CleanupP2Pmsg ( ); WSACleanup ( ); return 2; }
    std::printf ( "[acceptunnamed] control: accepted=%d child=[%ls] service=[%ls]\n",
                  oCtl.nAccepted, oCtl.strChild.c_str ( ), oCtl.strService.c_str ( ) );
    std::fflush ( stdout );
    if ( oCtl.nAccepted == 0 || oCtl.bChildNull || oCtl.strChild != oCtl.strService )
    {
        std::printf ( "\nRESULT: INCONCLUSIVE - the control did not see a child named\n"
                      "  like its listener, so an empty address below would prove\n"
                      "  nothing about the bit.\n" );
        CleanupP2Pmsg ( ); WSACleanup ( );
        return 3;
    }

    // ---- phase 2: the bit -----------------------------------------------------
    Log ( "--- phase 2: ConState_AcceptUnnamed, the child must start unnamed ---" );
    Seen oRun;
    if ( RunPhase ( nPort, true, oRun ) != 0 ) { CleanupP2Pmsg ( ); WSACleanup ( ); return 2; }
    std::printf ( "[acceptunnamed] bit:     accepted=%d child=[%ls] service=[%ls] child-has-bit=%s\n",
                  oRun.nAccepted, oRun.strChild.c_str ( ), oRun.strService.c_str ( ),
                  oRun.bChildHasBit ? "yes" : "no" );
    std::fflush ( stdout );

    if ( oRun.nAccepted == 0 )
    { std::printf ( "FAIL: no accepted child was found\n" ); nExit = 1; }
    if ( oRun.nAccepted > 0 && !oRun.bChildNull )
    { std::printf ( "FAIL: the child was named [%ls], not left empty\n", oRun.strChild.c_str ( ) ); nExit = 1; }
    if ( oRun.bChildHasBit )
    { std::printf ( "FAIL: the child carries ConState_AcceptUnnamed; it accepts nothing\n" ); nExit = 1; }
    if ( oRun.strService != oCtl.strService )
    { std::printf ( "FAIL: the listener's own address moved: [%ls] -> [%ls]\n",
                    oCtl.strService.c_str ( ), oRun.strService.c_str ( ) ); nExit = 1; }

    CleanupP2Pmsg ( );
    WSACleanup ( );

    std::printf ( nExit == 0 ? "\nRESULT: PASS\n" : "\nRESULT: FAIL\n" );
    std::fflush ( stdout );
    return nExit;
}
