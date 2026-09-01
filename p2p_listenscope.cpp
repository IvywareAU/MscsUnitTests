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
// p2p_listenscope.cpp - SECURITY GATE TEST: can a SERVICE be told not to be
// reachable from off this machine, and can it be told which sources it will
// accept at all?
//
// BACKGROUND - the gap this closes. P2PeerConWsa::Listen() bound
// INADDR_ANY as a literal from the import until 2026-08-27, and there was no
// setting anywhere on the class to say otherwise. Every service this library
// has ever stood up has therefore been reachable from every interface its host
// routes, and a deployment that wanted less could only get it from OUTSIDE the
// process - in a firewall - where nothing in the library could read it back.
// That is asset S9 in THREAT_MODEL.md twice over: a protection that is off, and
// one that cannot be seen to be off.
//
// TWO MECHANISMS, and the reason there are two is the whole design:
//
//   * THE BIND (SetListenScope). The only restriction the KERNEL enforces. A
//     socket bound to 127.0.0.1 cannot be reached from another machine at all -
//     the SYN is refused by the stack and nothing this library parses ever sees
//     the bytes. Refer THREAT_MODEL.md B1/B2: everything before the login gate
//     runs on bytes with no provenance, so the cheapest defence there is is the
//     one that stops them arriving.
//
//   * THE ALLOW-LIST (AllowAcceptFrom). Tested at accept against
//     AcceptSourceKey() - getpeername(), the kernel, a peer that has said
//     nothing. It exists because a BIND CANNOT EXPRESS "THE LAN": binding to a
//     LAN interface's address restricts which INTERFACE accepts, not which
//     SOURCE reaches it, and a packet forwarded in from the internet by a NAT
//     arrives on that same interface and is accepted.
//
// WHAT IT DOES - raw sockets throughout, for p2p_acceptcap's reason: the
// adversary being modelled does not run this library and will not complete a
// handshake, so the test must not either.
//
//   --scope-only  Phase 1 (THE BIND).
//     1. CONTROL, and it runs FIRST: the same server with the DEFAULT scope
//        must be reachable on this host's own non-loopback address. Without it
//        a host whose firewall drops that address would report a working bind
//        restriction it does not have. A control that fails is INCONCLUSIVE
//        (exit 3), never FAIL - it is a fact about the host.
//     2. THE MEASUREMENT: restood with P2PeerConScope_Loopback, the same
//        connection to the same non-loopback address MUST be refused...
//     3. ...while 127.0.0.1 MUST still be served. Without this last one a
//        Listen() that simply failed would pass.
//
//   --filter-only Phase 2 (THE ALLOW-LIST), against AllowAcceptFrom("127.0.0.2")
//     on a service bound to ANY, with both caps off so nothing else can refuse
//     anything:
//     1. IsAcceptSourceAllowed() answers directly - the DECISION, not a
//        consequence of it. THREAT_MODEL.md §2 records what it cost to learn
//        that distinction: a gate that measured delivery passed against the
//        tree that had the defect.
//     2. A connection from 127.0.0.2 is SERVED. The positive control, and
//        without it a filter that refused everybody would pass.
//     3. A connection from 127.0.0.3 is CLOSED.
//     4. An unnameable source (key 0) is REFUSED. The fail-CLOSED rule, and the
//        deliberate opposite of SourceAtCapacity() one line away in
//        AcceptSpawn(): a bound that cannot see its subject must refuse nobody,
//        a policy that cannot see its subject must refuse it.
//     5. Malformed prefixes are REJECTED and add nothing - "10.1",
//        "0x0a000001", "256.1.1.1", "1.2.3.4/33". inet_addr() accepts the first
//        two as addresses somewhere else entirely, which is a convenience at a
//        prompt and a hazard in a policy file.
//
// TWO LOOPBACK ADDRESSES, no second machine and no privileges: 127.0.0.0/8 is
// loopback in its entirety on both platforms, and p2p_acceptcap has depended on
// bind() to 127.0.0.2 plus the server's getpeername() reporting it back since
// 2026-08-19.
//
// VERDICT = process EXIT CODE:
//   0  PASS   the restriction bound, and the permitted case was still served
//   1  FAIL   a restricted source was served, or a permitted one was refused
//   2  SETUP  startup / listen failure, or this host has no route off itself,
//             so there is no address the bind restriction can be measured
//             against
//   3  INCONCLUSIVE a control failed, so the refusals prove nothing

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kServerAddr = L"Scope.Server";
static const P2PaddrSTR kDomain     = L"Scope.*";

static void Log ( const char *msg )
{
    std::printf ( "[listenscope] %s\n", msg );
    std::fflush ( stdout );
}

// ---------------------------------------------------------------------------
//  A raw TCP peer, optionally from a NOMINATED local address.
//  NOTES: Lifted from p2p_acceptcap, deliberately unchanged. The source PORT is
//         left to the kernel (port 0) because it differs on every connection by
//         design - which is exactly why it is not part of the accounting key
//         and not part of a prefix
// ---------------------------------------------------------------------------
static SOCKET RawConnectFromTo ( const char *szSource
                               , const char *szTarget, short nPort )
{
    SOCKET s = socket ( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    if ( s == INVALID_SOCKET ) return INVALID_SOCKET;

    if ( szSource )
    {
      sockaddr_in oLocal;
      std::memset ( &oLocal, 0, sizeof(oLocal) );
      oLocal.sin_family      = AF_INET;
      oLocal.sin_port        = 0;
      oLocal.sin_addr.s_addr = inet_addr ( szSource );
      if ( bind ( s, (sockaddr *)&oLocal, sizeof(oLocal) ) == SOCKET_ERROR )
      { closesocket ( s ); return INVALID_SOCKET; }
    }

    sockaddr_in oAddr;
    std::memset ( &oAddr, 0, sizeof(oAddr) );
    oAddr.sin_family      = AF_INET;
    oAddr.sin_port        = htons ( (u_short)nPort );
    oAddr.sin_addr.s_addr = inet_addr ( szTarget );

    if ( connect ( s, (sockaddr *)&oAddr, sizeof(oAddr) ) == SOCKET_ERROR )
    { closesocket ( s ); return INVALID_SOCKET; }

    return s;
}

//  Has the far end closed this socket?
//  NOTES: Lifted whole from p2p_acceptcap, whose banner records why neither
//         SO_RCVTIMEO nor select() can be used here. Non-blocking poll, keyed
//         on recv() == 0 for an orderly close, and treating an unrecognised
//         error as CLOSED because an abortive close surfaces as SOCKET_ERROR
//         and the error CODE is the one thing that is not portable across the
//         Platform shim
static bool WasClosedByPeer ( SOCKET s, DWORD dwWaitMs )
{
    if ( s == INVALID_SOCKET ) return true;

    DWORD dwArg = 1;
    ioctlsocket ( s, FIONBIO, &dwArg );

    for ( DWORD dwWaited = 0; ; dwWaited += 50 )
    {
        char      szBuf[64];
        const int r = recv ( s, szBuf, (int)sizeof(szBuf), 0 );
        if ( r == 0 ) return true;                   // orderly close: gone
        if ( r  > 0 ) return false;                  // it spoke: still up

        const int nErr = WSAGetLastError ( );
        const bool bWaiting = ( nErr == WSAEWOULDBLOCK ) ||
                              ( nErr == (int)ERROR_SHARING_VIOLATION );
        if ( !bWaiting ) return true;                // reset, or gone

        if ( dwWaited >= dwWaitMs ) return false;    // never spoke: still up
        Sleep ( 50 );
    }
}

static void RawClose ( SOCKET &s )
{
    if ( s != INVALID_SOCKET ) { closesocket ( s ); s = INVALID_SOCKET; }
}

//  This host's own non-loopback IPv4 address, dotted.
//  NOTES: The address the bind restriction is MEASURED against, so a host that
//         has none makes the test inconclusive rather than passing it - which
//         is why the caller reports SETUP on an empty answer and does not
//         quietly fall back to 127.0.0.1. Falling back would compare loopback
//         against loopback and pass on a tree with no restriction in it at all.
//       : ASKS THE ROUTING TABLE, not the resolver, and that is the whole point
//         of this function's second version. The first resolved gethostname()'s
//         answer through getaddrinfo(), which is a WINDOWS convention: there a
//         machine's name maps to the address it is reachable on. On Debian and
//         Ubuntu the installer writes `127.0.1.1 <hostname>` into /etc/hosts,
//         so the name resolves to LOOPBACK and this function found nothing -
//         on a host sitting on 192.168.1.50 with the interface up. The gate
//         reported SETUP and skipped itself, which is the honest outcome of a
//         wrong question but is still a security gate that never ran. Measured
//         2026-08-28, the first time this test was ever run on Linux.
//       : The UDP-connect trick, which is the portable way to ask "which of my
//         addresses would the kernel use to reach off this machine". A
//         connect() on a DATAGRAM socket sends NOTHING - it only fixes the
//         socket's local end from the routing table - so this touches no
//         network, needs no privilege, and cannot hang. getsockname() then
//         reports the address chosen. 192.0.2.1 is TEST-NET-1 (RFC 5737),
//         reserved for documentation and guaranteed never to be a host we
//         could accidentally contact even if a packet were sent.
//       : A host with no route off itself answers false, and so does one whose
//         only route is loopback. Both are the SETUP outcome the caller wants:
//         the restriction cannot be measured, rather than measured and passed.
static bool LocalNonLoopbackV4 ( char *szOut, size_t cchOut )
{
    if ( cchOut == 0 ) return false;
    szOut[0] = 0;

    SOCKET s = socket ( AF_INET, SOCK_DGRAM, 0 );
    if ( s == INVALID_SOCKET ) return false;

    sockaddr_in oProbe;
    std::memset ( &oProbe, 0, sizeof(oProbe) );
    oProbe.sin_family      = AF_INET;
    oProbe.sin_port        = htons ( 53 );           // arbitrary; nothing is sent
    oProbe.sin_addr.s_addr = inet_addr ( "192.0.2.1" );   // RFC5737 TEST-NET-1

    bool bFound = false;
    if ( connect ( s, (sockaddr *)&oProbe, sizeof(oProbe) ) != SOCKET_ERROR )
    {
      sockaddr_in oLocal;
      std::memset ( &oLocal, 0, sizeof(oLocal) );
      socklen_t nLen = (socklen_t)sizeof(oLocal);
      if ( getsockname ( s, (sockaddr *)&oLocal, &nLen ) != SOCKET_ERROR )
      {
        const unsigned long ulHost =
          (unsigned long) ntohl ( (u_long)oLocal.sin_addr.s_addr );
        //  Loopback and the unspecified address are both "no answer" here, for
        //  the reason in the banner: a control run against 127.0.0.1 proves
        //  nothing about a bind that restricts to 127.0.0.1
        if ( ( ulHost >> 24 ) != 127 && ulHost != 0 )
        {
          _snprintf_s ( szOut, cchOut, _TRUNCATE, "%u.%u.%u.%u"
                      ,(unsigned)((ulHost >> 24) & 0xFF)
                      ,(unsigned)((ulHost >> 16) & 0xFF)
                      ,(unsigned)((ulHost >>  8) & 0xFF)
                      ,(unsigned)( ulHost        & 0xFF) );
          bFound = true;
        }
      }
    }

    closesocket ( s );
    return bFound;
}

// =========================================================================
class ScopeHub : public P2PeerHub
{
public:
    ScopeHub ( P2PaddrSTR strAddr ) : P2PeerHub ( strAddr ) { }
    virtual ~ScopeHub ( ) { }
};

//  Stands a server up, runs one probe against it, tears it down.
//  NOTES: A fresh hub per scope rather than one hub re-scoped, because
//         SetListenScope() is documented to take effect at the NEXT Listen()
//         and a test that relied on anything else would be measuring a promise
//         the header does not make
static bool ProbeUnderScope ( P2PeerConScope_e eScope
                            , const char      *szBindAddress
                            , short            nPort
                            , const char      *szTarget
                            , bool            &rbConnected )
{
    rbConnected = false;

    if ( !StartupP2Pmsg ( 16 ) ) return false;
    {
        ScopeHub oServer ( kServerAddr );
        //  RequireAuth(false): this binary measures admission at the SOCKET,
        //  which is decided before a login is attempted and would be decided
        //  the same way if one never was. Refer p2p_authgate for the gate that
        //  measures who may speak
        oServer.RequireAuth ( false );
        HANDLE hThread = oServer.SpawnHub ( );
        if ( !hThread ) { CleanupP2Pmsg ( ); return false; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { oServer.CloseHub ( ); CleanupP2Pmsg ( ); return false; }

        pSvc -> SetListenScope   ( eScope, CString ( szBindAddress ) );
        pSvc -> SetMaxAccepted   ( 0 );        // nothing else may refuse
        pSvc -> SetLoginDeadline ( 0 );        // nothing else may close
        oServer.PostP2PeerCon ( pSvc );
        Sleep ( 700 );

        SOCKET s = RawConnectFromTo ( 0, szTarget, nPort );
        rbConnected = ( s != INVALID_SOCKET );
        RawClose ( s );
        Sleep ( 300 );

        oServer.CloseHub ( );
        WaitForSingleObject ( hThread, 3000 );
        CloseHandle ( hThread );
    }
    CleanupP2Pmsg ( );
    return true;
}

// =========================================================================
//  Phase 1 - THE BIND
// =========================================================================
static int ScopeOnly ( short nPort )
{
    std::printf ( "=== p2p_listenscope --scope-only (port %d) ===\n", (int)nPort );
    std::fflush ( stdout );

    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    char szLan[64] = { 0 };
    if ( !LocalNonLoopbackV4 ( szLan, sizeof(szLan) ) )
    {
      Log ( "SETUP: this host has no non-loopback IPv4 address to measure "
            "against" );
      WSACleanup ( );
      return 2;
    }
    std::printf ( "[listenscope] measuring against local address %s\n", szLan );
    std::fflush ( stdout );

    // 1. THE CONTROL, first. Default scope must be reachable on that address
    bool bControl = false;
    if ( !ProbeUnderScope ( P2PeerConScope_Any, 0, nPort, szLan, bControl ) )
    { Log ( "SETUP: server would not start for the control" ); WSACleanup(); return 2; }

    if ( !bControl )
    {
      Log ( "INCONCLUSIVE: the DEFAULT scope was not reachable on this host's "
            "own address - a firewall, most likely. The restriction below "
            "would be indistinguishable from it" );
      WSACleanup ( );
      return 3;
    }
    Log ( "control: default scope reachable on the non-loopback address" );

    // 2. THE MEASUREMENT. Loopback scope must NOT be reachable there
    bool bOffHost = false;
    if ( !ProbeUnderScope ( P2PeerConScope_Loopback, 0, nPort, szLan, bOffHost ) )
    { Log ( "SETUP: server would not start under the loopback scope" ); WSACleanup(); return 2; }

    // 3. ...and 127.0.0.1 must still be served
    bool bLoopback = false;
    if ( !ProbeUnderScope ( P2PeerConScope_Loopback, 0, nPort, "127.0.0.1", bLoopback ) )
    { Log ( "SETUP: server would not start under the loopback scope" ); WSACleanup(); return 2; }

    WSACleanup ( );

    std::printf ( "\n--- RESULT ---\n"
                  "  default  scope, %-15s : %s\n"
                  "  loopback scope, %-15s : %s\n"
                  "  loopback scope, %-15s : %s\n"
                , szLan,        bControl  ? "connected (expected)" : "REFUSED"
                , szLan,        bOffHost  ? "CONNECTED"            : "refused (expected)"
                , "127.0.0.1",  bLoopback ? "connected (expected)" : "REFUSED" );

    if ( bOffHost )
    {
      Log ( "FAIL: P2PeerConScope_Loopback was still reachable from this "
            "host's routable address" );
      return 1;
    }
    if ( !bLoopback )
    {
      Log ( "FAIL: P2PeerConScope_Loopback refused 127.0.0.1 as well - a bind "
            "that fails is not a bind that is narrow" );
      return 1;
    }

    Log ( "PASS: the bind narrowed to this machine and stayed served on it" );
    return 0;
}

// =========================================================================
//  Phase 2 - THE ALLOW-LIST
// =========================================================================
static int FilterOnly ( short nPort )
{
    std::printf ( "=== p2p_listenscope --filter-only (port %d) ===\n", (int)nPort );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    int nVerdict = 0;
    {
        ScopeHub oServer ( kServerAddr );
        oServer.RequireAuth ( false );      // see the scope phase above
        HANDLE hThread = oServer.SpawnHub ( );
        if ( !hThread ) { Log ( "SETUP: SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }

        // 5. THE PARSER, before anything opens a socket. A rule that is not
        //    understood must be reported and must add NOTHING - a filter that
        //    silently swallowed a bad line would be narrower in the operator's
        //    belief than in the socket
        const bool bNullRejected = !pSvc -> AllowAcceptFrom ( 0 );
        const bool bShortRejected= !pSvc -> AllowAcceptFrom ( _T("10.1") );
        const bool bHexRejected  = !pSvc -> AllowAcceptFrom ( _T("0x0a000001") );
        const bool bOctetRejected= !pSvc -> AllowAcceptFrom ( _T("256.1.1.1") );
        const bool bBitsRejected = !pSvc -> AllowAcceptFrom ( _T("1.2.3.4/33") );
        const bool bStillEmpty   = !pSvc -> HasAcceptSourceFilter ( );

        // 4. FAIL-CLOSED, and it can only be measured while the list is empty
        //    for the negative half: an unfiltered service admits anyone,
        //    including an origin it cannot name
        const bool bUnfilteredAdmitsUnnameable = pSvc -> IsAcceptSourceAllowed ( 0 );

        if ( !pSvc -> AllowAcceptFrom ( _T("127.0.0.2") ) )
        { Log ( "SETUP: a well-formed prefix was rejected" ); return 2; }

        // 1. THE DECISION ITSELF, asked directly
        const P2PsourceKey xTwo   = (P2PsourceKey)(unsigned int) inet_addr ( "127.0.0.2" );
        const P2PsourceKey xThree = (P2PsourceKey)(unsigned int) inet_addr ( "127.0.0.3" );
        const bool bTwoAllowed    =  pSvc -> IsAcceptSourceAllowed ( xTwo   );
        const bool bThreeRefused  = !pSvc -> IsAcceptSourceAllowed ( xThree );
        const bool bZeroRefused   = !pSvc -> IsAcceptSourceAllowed ( 0      );

        //  Both caps OFF, so nothing but the allow-list can refuse anything
        pSvc -> SetMaxAccepted          ( 0 );
        pSvc -> SetMaxAcceptedPerSource ( 0 );
        pSvc -> SetLoginDeadline        ( 0 );
        oServer.PostP2PeerCon ( pSvc );
        Sleep ( 700 );

        Log ( "server listening on ANY; AllowAcceptFrom(\"127.0.0.2\")" );

        // 2. + 3. THE SOCKETS
        SOCKET sAllowed = RawConnectFromTo ( "127.0.0.2", "127.0.0.1", nPort );
        SOCKET sRefused = RawConnectFromTo ( "127.0.0.3", "127.0.0.1", nPort );
        if ( sAllowed == INVALID_SOCKET || sRefused == INVALID_SOCKET )
        {
          Log ( "SETUP: this host would not lend two loopback source addresses" );
          RawClose ( sAllowed ); RawClose ( sRefused );
          oServer.CloseHub ( );
          WaitForSingleObject ( hThread, 3000 );
          CloseHandle ( hThread );
          CleanupP2Pmsg ( );
          WSACleanup ( );
          return 2;
        }

        const bool bRefusedClosed = WasClosedByPeer ( sRefused, 2000 );
        const bool bAllowedUp     = !WasClosedByPeer ( sAllowed, 1000 );
        RawClose ( sAllowed ); RawClose ( sRefused );

        std::printf ( "\n--- RESULT ---\n"
                      "  IsAcceptSourceAllowed(127.0.0.2)  : %s\n"
                      "  IsAcceptSourceAllowed(127.0.0.3)  : %s\n"
                      "  IsAcceptSourceAllowed(unnameable) : %s\n"
                      "  unfiltered admits unnameable      : %s\n"
                      "  connection from 127.0.0.2         : %s\n"
                      "  connection from 127.0.0.3         : %s\n"
                      "  malformed prefixes rejected       : %s\n"
                      "  ...and added nothing              : %s\n"
                    , bTwoAllowed   ? "allowed (expected)" : "REFUSED"
                    , bThreeRefused ? "refused (expected)" : "ALLOWED"
                    , bZeroRefused  ? "refused (expected)" : "ALLOWED"
                    , bUnfilteredAdmitsUnnameable ? "yes (expected)" : "NO"
                    , bAllowedUp     ? "served (expected)"  : "CLOSED"
                    , bRefusedClosed ? "closed (expected)"  : "SERVED"
                    , ( bNullRejected && bShortRejected && bHexRejected &&
                        bOctetRejected && bBitsRejected ) ? "yes (expected)" : "NO"
                    , bStillEmpty ? "yes (expected)" : "NO" );
        std::fflush ( stdout );

        if ( !bAllowedUp )
        {
          Log ( "INCONCLUSIVE: the PERMITTED source was closed too, so the "
                "refusal below proves nothing about the allow-list" );
          nVerdict = 3;
        }
        else if ( !bRefusedClosed )
        { Log ( "FAIL: a source not on the allow-list was served" ); nVerdict = 1; }
        else if ( !bTwoAllowed || !bThreeRefused )
        { Log ( "FAIL: IsAcceptSourceAllowed() disagrees with the socket" ); nVerdict = 1; }
        else if ( !bZeroRefused )
        { Log ( "FAIL: a configured allow-list admitted an unnameable source - "
                "it must fail CLOSED" ); nVerdict = 1; }
        else if ( !bUnfilteredAdmitsUnnameable )
        { Log ( "FAIL: an UNCONFIGURED service refused an unnameable source - "
                "no policy must mean no refusal" ); nVerdict = 1; }
        else if ( !( bNullRejected && bShortRejected && bHexRejected &&
                     bOctetRejected && bBitsRejected && bStillEmpty ) )
        { Log ( "FAIL: a malformed prefix was accepted, so the filter is not "
                "the one the operator wrote" ); nVerdict = 1; }
        else
          Log ( "PASS: only the permitted source was served, and the rules are "
                "the ones that were written" );

        oServer.CloseHub ( );
        WaitForSingleObject ( hThread, 3000 );
        CloseHandle ( hThread );
    }
    CleanupP2Pmsg ( );
    WSACleanup ( );
    return nVerdict;
}

// =========================================================================
int main ( int argc, char **argv )
{
    short nPort      = 7847;
    bool  bScopeOnly = false;
    bool  bFilterOnly= false;

    for ( int i = 1; i < argc; ++i )
    {
      if      ( std::strcmp ( argv[i], "--scope-only"  ) == 0 ) bScopeOnly  = true;
      else if ( std::strcmp ( argv[i], "--filter-only" ) == 0 ) bFilterOnly = true;
      else
      {
        const int n = std::atoi ( argv[i] );
        if ( n > 100 && n < 65536 ) nPort = (short)n;
      }
    }

    //  One mode, one verdict, one exit code - p2p_acceptcap's rule, and the
    //  reason its phases became separate ctest targets off one source
    if ( bFilterOnly ) return FilterOnly ( nPort );
    if ( bScopeOnly  ) return ScopeOnly  ( nPort );

    std::printf ( "usage: p2p_listenscope [port] --scope-only | --filter-only\n" );
    return 2;
}
