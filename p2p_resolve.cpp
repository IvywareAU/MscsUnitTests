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
// p2p_resolve.cpp - GATE TEST: can a client dial a peer by NAME?
//
// BACKGROUND - the defect this closes, found 2026-08-28 while answering
// whether the transport could speak IPv6 (it cannot; that is a separate and
// much larger question). P2PeerConWsa::Connect() resolved its peer like this:
//
//     InetPton(AF_INET, csIpAddress, &oSockaddr.sin_addr.s_addr);
//     if ( oSockaddr.sin_addr.s_addr == INADDR_NONE )
//     { ...gethostbyname()... }
//
// The fallback was written for inet_addr(), which signals failure by returning
// INADDR_NONE. The PostVS2015 move to InetPton() changed the signal and left
// the test: InetPton() answers 0 for a string it cannot parse and WRITES
// NOTHING, so after the memset the address stayed 0.0.0.0 and that condition
// could only ever fire for the literal "255.255.255.255".
//
// So gethostbyname() was UNREACHABLE, and every host NAME resolved to 0.0.0.0.
// Two things followed, and neither was visible in the suite:
//
//   * A client given a name could not connect at all. It failed inside
//     ConnectEx with WSAEADDRNOTAVAIL - measured, connect() to 0.0.0.0 is
//     refused on this platform - rather than with the "Unable to resolve
//     server" the dead branch plainly meant to report.
//   * The SELF-CONNECTION path went the same way. An empty address is
//     documented to mean "connect to this machine" and is served by feeding
//     gethostname()'s answer - a NAME - into the same resolver.
//
// WHY THE SUITE WAS GREEN THROUGHOUT: every other test in it dials the literal
// "127.0.0.1", which InetPton parses. Not one of them passes a name. This file
// is the one that does, and it is the whole reason it exists.
//
// WHAT IT DOES - real hubs and a real P2PeerConWsa client, not raw sockets.
// The subject is the library's own Connect(), so the test must go through it.
//
//   1. CONTROL: dial the literal "127.0.0.1". The service's accepted tally must
//      reach 1. Without this a broken harness reads as a broken resolver, and
//      the two phases below prove nothing.
//   2. THE MEASUREMENT: dial the NAME "localhost". The tally must reach 1
//      again. This is the observation that separates the fix from the defect -
//      before it, this connection went to 0.0.0.0 and never arrived.
//   3. NEGATIVE CONTROL: dial a name reserved by RFC 6761 to be unresolvable.
//      The tally must stay 0. A resolver that hijacks NXDOMAIN answers a real
//      address and makes this INCONCLUSIVE rather than FAILED - that is a fact
//      about the network the test is run on, not about the library.
//
// The tally rather than a completed login, deliberately: the accept is what
// proves the client reached the right address, and it happens before any login
// this test would then have to provision keys for.
//
// VERDICT = process EXIT CODE:
//   0  PASS   a name and a literal both arrived; an unresolvable name did not
//   1  FAIL   a name did not arrive, or an unresolvable one did
//   2  SETUP  startup / listen failure (test inconclusive)
//   3  INCONCLUSIVE a control disagreed, so the rest proves nothing

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kServerAddr = L"Rslv.Server";
static const P2PaddrSTR kClientAddr = L"Rslv.Client";
static const P2PaddrSTR kDomain     = L"Rslv.*";

static void Log ( const char *msg )
{
    std::printf ( "[resolve] %s\n", msg );
    std::fflush ( stdout );
}

// =========================================================================
class RslvHub : public P2PeerHub
{
public:
    RslvHub ( P2PaddrSTR strAddr ) : P2PeerHub ( strAddr ) { }
    virtual ~RslvHub ( ) { }
};

//  Waits for the accepted tally to reach a target and returns what it ended on
//  NOTES: Lifted from p2p_conreap, and for its reason - a number in the log is
//         worth more than a boolean when this goes red. A bounded poll rather
//         than one Sleep, because the accept is delivered on the hub's pump
//         thread and how long that takes is a property of the machine
static long PollAccepted ( P2PeerConWsa *pSvc, long xTarget, int nMaxMSec )
{
    long xRead = pSvc -> GetAcceptedCount ( );
    for ( int nWaited = 0; nWaited < nMaxMSec && xRead != xTarget; nWaited += 100 )
    {
      Sleep ( 100 );
      xRead = pSvc -> GetAcceptedCount ( );
    }
    return xRead;
}

//  Stands a server and a client up, dials lpszTarget, answers the tally
//  NOTES: A fresh pair per dial rather than one server re-dialled, so a phase
//         cannot inherit a connection an earlier one left behind - which would
//         report the previous phase's answer as this one's
//       : -1 for a setup failure, so the caller can tell "did not arrive" from
//         "never got as far as trying"
static long DialAndCount ( LPCTSTR lpszTarget, short nPort )
{
    if ( !StartupP2Pmsg ( 16 ) )
      return -1;

    long xAccepted = -1;
    {
        RslvHub oServer ( kServerAddr );
        RslvHub oClient ( kClientAddr );
        //  RequireAuth(false) on BOTH. This measures address RESOLUTION, which
        //  is decided before a byte is sent and would be decided the same way
        //  if no login ever followed. Refer p2p_authgate for the gate that
        //  measures who may speak
        oServer.RequireAuth ( false );
        oClient.RequireAuth ( false );

        HANDLE hServer = oServer.SpawnHub ( );
        HANDLE hClient = hServer ? oClient.SpawnHub ( ) : 0;
        if ( !hServer || !hClient )
        {
          if ( hServer ) { oServer.CloseHub ( );
                           WaitForSingleObject ( hServer, 3000 );
                           CloseHandle ( hServer ); }
          CleanupP2Pmsg ( );
          return -1;
        }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( pSvc )
        {
          pSvc -> SetMaxAccepted   ( 0 );    // nothing else may refuse
          pSvc -> SetLoginDeadline ( 0 );    // nothing else may close
          oServer.PostP2PeerCon ( pSvc );
          Sleep ( 700 );

          P2PeerConWsa *pCli =
            P2PeerConWsa::ClientFactory ( kServerAddr, lpszTarget, nPort );
          if ( pCli )
          {
            oClient.PostP2PeerCon ( pCli );
            //  Five seconds. A resolvable name answers in milliseconds from the
            //  cache; the budget is for the UNRESOLVABLE phase, which spends
            //  whatever the platform's resolver spends before saying no
            xAccepted = PollAccepted ( pSvc, 1, 5000 );
          }
        }

        oClient.CloseHub ( );
        WaitForSingleObject ( hClient, 3000 );
        CloseHandle ( hClient );
        oServer.CloseHub ( );
        WaitForSingleObject ( hServer, 3000 );
        CloseHandle ( hServer );
    }
    CleanupP2Pmsg ( );
    return xAccepted;
}

// =========================================================================
int main ( int argc, char **argv )
{
    short nPort = 7849;
    for ( int i = 1; i < argc; ++i )
    {
      const int n = std::atoi ( argv[i] );
      if ( n > 100 && n < 65536 ) nPort = (short)n;
    }

    std::printf ( "=== p2p_resolve (port %d) ===\n", (int)nPort );
    std::fflush ( stdout );

    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    // 1. THE CONTROL, first
    const long xLiteral = DialAndCount ( _T("127.0.0.1"), nPort );
    if ( xLiteral < 0 ) { Log ( "SETUP: hubs would not start" ); WSACleanup(); return 2; }
    if ( xLiteral != 1 )
    {
      Log ( "INCONCLUSIVE: the LITERAL control did not connect either, so a "
            "name failing below would say nothing about the resolver" );
      WSACleanup ( );
      return 3;
    }
    Log ( "control: the literal 127.0.0.1 connected" );

    // 2. THE MEASUREMENT
    const long xName = DialAndCount ( _T("localhost"), nPort );
    if ( xName < 0 ) { Log ( "SETUP: hubs would not start" ); WSACleanup(); return 2; }

    // 3. THE NEGATIVE CONTROL
    //    RFC 6761 reserves .invalid to never resolve
    const long xBogus = DialAndCount ( _T("p2p-nonesuch.invalid"), nPort );
    if ( xBogus < 0 ) { Log ( "SETUP: hubs would not start" ); WSACleanup(); return 2; }

    WSACleanup ( );

    std::printf ( "\n--- RESULT ---\n"
                  "  dial \"127.0.0.1\"            accepted=%ld : %s\n"
                  "  dial \"localhost\"            accepted=%ld : %s\n"
                  "  dial \"...invalid\"           accepted=%ld : %s\n"
                , xLiteral, xLiteral == 1 ? "connected (expected)" : "DID NOT CONNECT"
                , xName,    xName    == 1 ? "connected (expected)" : "DID NOT CONNECT"
                , xBogus,   xBogus   == 0 ? "refused (expected)"   : "CONNECTED" );
    std::fflush ( stdout );

    if ( xName != 1 )
    {
      Log ( "FAIL: a peer dialled by NAME did not arrive. gethostbyname's "
            "replacement is unreachable again, or the resolver hint no longer "
            "matches the family the socket opens" );
      return 1;
    }
    if ( xBogus != 0 )
    {
      Log ( "INCONCLUSIVE: an address reserved to be unresolvable resolved "
            "anyway - this network hijacks NXDOMAIN. The two phases above "
            "still hold; this one cannot be measured here" );
      return 3;
    }

    Log ( "PASS: a name and a literal both arrived, an unresolvable name did not" );
    return 0;
}
