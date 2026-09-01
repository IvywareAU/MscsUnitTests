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
// p2p_ipv6.cpp - can this transport speak IPv6 at all, does a v6-only service
// really refuse v4, and does an allow-list mean the same thing on both sockets?
//
// BACKGROUND - the gap this closes. P2PeerConWsa opened AF_INET at all three
// socket sites - Listen(), Accept() and Connect() - and carried sockaddr_in for
// the bind and the dial, from the import until 2026-08-28. A v6 peer could not
// reach a service and a client could not dial one. What made that a DEFAULT
// rather than a limitation is that nothing said so and nothing could be told
// otherwise: Readme.md recorded "TCP is IPv4 only" and there was no setting to
// change it. SetFamily() is the setting; this file is what says it works.
//
// THREE THINGS ARE MEASURED, and they are separate because they can fail
// separately:
//
//   --v6-only   THE TRANSPORT, and the v6-only half of the family setting.
//     1. CONTROL, and it runs FIRST: the DEFAULT (IPv4) family must serve
//        127.0.0.1 on this host. Without it a host with no working loopback
//        reports a v6 transport that is not there. A control that fails is
//        SETUP (exit 2) - it is a fact about the host.
//     2. THE MEASUREMENT: P2PeerConFamily_IPv6 bound to ::1 must SERVE a raw
//        AF_INET6 client. Nothing before this date could.
//     3. ...and must REFUSE a v4 client on 127.0.0.1 at the same port. This is
//        IPV6_V6ONLY being set rather than inherited, and it is the half that
//        would pass silently on Windows and fail silently on Linux if the
//        option were left to the platform: Windows defaults it ON, most Linux
//        distributions default it OFF. A "v6-only" service that quietly admits
//        v4 is asset S9 in THREAT_MODEL.md - a protection whose real state
//        cannot be read off the code.
//
//   --dual      ONE SOCKET, BOTH FAMILIES. P2PeerConFamily_Dual on scope ANY
//        must serve a raw v6 client on ::1 AND a raw v4 client on 127.0.0.1.
//        Both halves are required: serving only v6 is IPV6_V6ONLY left on, and
//        serving only v4 is not a dual-stack socket at all.
//
//   --v6filter  THE ALLOW-LIST IN TWO FAMILIES, which is where the two address
//        spaces actually touch.
//     1. THE PARSER. "::1", "2001:db8::/32" and "fc00::/7" are understood;
//        "::1/129", "fe80::1%eth0" (a zone index, which no rule may carry) and
//        "gg::1" are REJECTED and add NOTHING. Same rule as the v4 half in
//        p2p_acceptfilter: a filter that silently swallowed a bad line would be
//        narrower in the operator's belief than in the socket.
//     2. THE DECISION, asked directly. A /32 rule admits an address inside it
//        and refuses one outside; a v4 rule does not admit a v6 peer and a v6
//        rule does not admit a v4 one.
//     3. V4-MAPPED NORMALISATION, END TO END, and it is the reason this phase
//        exists. A dual-stack socket reports a v4 peer as ::ffff:a.b.c.d. Left
//        alone, an operator's "127.0.0.0/8" would admit that peer on a v4
//        service and refuse it on a dual one, for no reason the operator can
//        see. So: a DUAL service allowing ONLY "127.0.0.0/8" must SERVE a v4
//        client (the normalisation) and CLOSE a v6 client on ::1 (the filter is
//        still a filter, and a list of v4 rules refuses every v6 source).
//
// RAW SOCKETS for the clients, for p2p_acceptcap's reason: the subject is
// admission at the SOCKET, decided before a login is attempted and decided the
// same way if one never is.
//
// VERDICT = process EXIT CODE:
//   0  PASS   the family was honoured and the allow-list meant one thing
//   1  FAIL   a refused peer was served, or a permitted one was refused
//   2  SETUP  startup / listen failure, or this host has no usable loopback
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
static const P2PaddrSTR kServerAddr = L"Ipv6.Server";
static const P2PaddrSTR kDomain     = L"Ipv6.*";

static void Log ( const char *msg )
{
    std::printf ( "[ipv6] %s\n", msg );
    std::fflush ( stdout );
}

// ---------------------------------------------------------------------------
//  A raw TCP peer of a nominated family.
//  NOTES: getaddrinfo() with AI_NUMERICHOST rather than two hand-built
//         sockaddrs, so the harness parses an address the same way the library
//         does and a difference between them cannot be read as a defect in the
//         subject
// ---------------------------------------------------------------------------
static SOCKET RawConnect ( int nFamily, const char *szTarget, short nPort )
{
    char szPort[16];
    _snprintf_s ( szPort, sizeof(szPort), _TRUNCATE, "%u"
                , (unsigned)(unsigned short)nPort );

    addrinfo  oHints;
    addrinfo *pResult = 0;
    std::memset ( &oHints, 0, sizeof(oHints) );
    oHints.ai_family   = nFamily;
    oHints.ai_socktype = SOCK_STREAM;
    oHints.ai_protocol = IPPROTO_TCP;
    oHints.ai_flags    = AI_NUMERICHOST;

    if ( getaddrinfo ( szTarget, szPort, &oHints, &pResult ) != 0 || !pResult )
      return INVALID_SOCKET;

    SOCKET s = socket ( pResult->ai_family, pResult->ai_socktype
                      , pResult->ai_protocol );
    if ( s != INVALID_SOCKET &&
         connect ( s, pResult->ai_addr, (int)pResult->ai_addrlen )
         == SOCKET_ERROR )
    { closesocket ( s ); s = INVALID_SOCKET; }

    freeaddrinfo ( pResult );
    return s;
}

//  Has the far end closed this socket?
//  NOTES: Lifted whole from p2p_listenscope, whose banner records why neither
//         SO_RCVTIMEO nor select() can be used here
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

//  Does this host have a working IPv6 loopback at all?
//  NOTES: Asked before anything is measured, so a machine with the v6 stack
//         disabled reports SETUP rather than FAIL. A test that cannot tell "the
//         library will not do this" from "this host will not do this" is not a
//         gate, and the distinction is not theoretical - a v6-disabled Windows
//         image is a supported deployment
static bool HostHasIPv6 ( )
{
    SOCKET s = socket ( AF_INET6, SOCK_STREAM, IPPROTO_TCP );
    if ( s == INVALID_SOCKET )
      return false;

    sockaddr_in6 oAddr;
    std::memset ( &oAddr, 0, sizeof(oAddr) );
    oAddr.sin6_family        = AF_INET6;
    oAddr.sin6_port          = 0;                    // any free port
    oAddr.sin6_addr.s6_addr[15] = 1;                 // ::1
    const bool bOk = ( bind ( s, (sockaddr *)&oAddr, sizeof(oAddr) ) == 0 );
    closesocket ( s );
    return bOk;
}

// =========================================================================
class Ipv6Hub : public P2PeerHub
{
public:
    Ipv6Hub ( P2PaddrSTR strAddr ) : P2PeerHub ( strAddr ) { }
    virtual ~Ipv6Hub ( ) { }
};

//  What one probe against one stood-up service asked and got back
struct Probe
{
    int          nFamily;              // AF_INET or AF_INET6
    const char  *szTarget;             // numeric, of that family
    bool         bConnected;           // the TCP handshake completed
    bool         bServed;              // ...and the service did not close it
};

//  Stands a server up under one family/scope, runs every probe against it,
//  tears it down.
//  NOTES: A fresh hub per configuration rather than one hub re-configured,
//         because SetFamily() and SetListenScope() are both documented to take
//         effect at the NEXT Listen() and a test that relied on anything else
//         would be measuring a promise the header does not make
//       : Every probe runs against the SAME service instance, deliberately.
//         The v6-only phase asks one socket to serve v6 and refuse v4, which is
//         one fact about one socket and not two facts about two
static bool ProbeService ( P2PeerConFamily_e eFamily
                         , P2PeerConScope_e  eScope
                         , const char       *szBindAddress
                         , const char       *szAllowPrefix
                         , short             nPort
                         , Probe            *pProbes
                         , int               nProbes )
{
    for ( int i = 0; i < nProbes; ++i )
    { pProbes[i].bConnected = false; pProbes[i].bServed = false; }

    if ( !StartupP2Pmsg ( 16 ) ) return false;
    bool bStood = false;
    {
        Ipv6Hub oServer ( kServerAddr );
        //  RequireAuth(false): this binary measures admission at the SOCKET,
        //  which is decided before a login is attempted and would be decided
        //  the same way if one never was. Refer p2p_authgate for the gate that
        //  measures who may speak
        oServer.RequireAuth ( false );
        HANDLE hThread = oServer.SpawnHub ( );
        if ( !hThread ) { CleanupP2Pmsg ( ); return false; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc )
        { oServer.CloseHub ( ); CleanupP2Pmsg ( ); return false; }

        pSvc -> SetFamily      ( eFamily );
        pSvc -> SetListenScope ( eScope, CString ( szBindAddress ) );
        if ( szAllowPrefix )
          pSvc -> AllowAcceptFrom ( CString ( szAllowPrefix ) );
        //  Both caps OFF and no login deadline, so nothing but the family and
        //  the allow-list can refuse or close anything
        pSvc -> SetMaxAccepted          ( 0 );
        pSvc -> SetMaxAcceptedPerSource ( 0 );
        pSvc -> SetLoginDeadline        ( 0 );
        oServer.PostP2PeerCon ( pSvc );
        Sleep ( 700 );

        for ( int i = 0; i < nProbes; ++i )
        {
          SOCKET s = RawConnect ( pProbes[i].nFamily, pProbes[i].szTarget
                                , nPort );
          pProbes[i].bConnected = ( s != INVALID_SOCKET );
          //  SERVED means connected AND not closed. A service that refuses at
          //  accept still completes the handshake - the kernel does that - and
          //  then closes, so the connect() alone cannot tell an admission from
          //  a refusal. Refer p2p_acceptfilter, which learned the same thing
          if ( pProbes[i].bConnected )
            pProbes[i].bServed = !WasClosedByPeer ( s, 1500 );
          RawClose ( s );
          Sleep ( 200 );
        }

        oServer.CloseHub ( );
        WaitForSingleObject ( hThread, 3000 );
        CloseHandle ( hThread );
        bStood = true;
    }
    CleanupP2Pmsg ( );
    return bStood;
}

// =========================================================================
//  Phase 1 - THE TRANSPORT, and IPV6_V6ONLY
// =========================================================================
static int V6Only ( short nPort )
{
    std::printf ( "=== p2p_ipv6 --v6-only (port %d) ===\n", (int)nPort );
    std::fflush ( stdout );

    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    if ( !HostHasIPv6 ( ) )
    {
      Log ( "SETUP: this host will not bind ::1, so it has no IPv6 stack to "
            "measure the library against" );
      WSACleanup ( );
      return 2;
    }

    // 1. THE CONTROL, first. The DEFAULT family must serve 127.0.0.1
    Probe oControl[1] = { { AF_INET, "127.0.0.1", false, false } };
    if ( !ProbeService ( P2PeerConFamily_IPv4, P2PeerConScope_Loopback, 0, 0
                       , nPort, oControl, 1 ) )
    { Log ( "SETUP: server would not start for the control" );
      WSACleanup ( ); return 2; }

    if ( !oControl[0].bServed )
    {
      Log ( "INCONCLUSIVE: the DEFAULT family did not serve 127.0.0.1 on this "
            "host, so nothing measured below would mean what it says" );
      WSACleanup ( );
      return 3;
    }
    Log ( "control: the IPv4 family serves 127.0.0.1" );

    // 2. + 3. THE MEASUREMENT. One v6-only service, asked both questions
    Probe oV6[2] = { { AF_INET6, "::1",       false, false }
                   , { AF_INET,  "127.0.0.1", false, false } };
    if ( !ProbeService ( P2PeerConFamily_IPv6, P2PeerConScope_Loopback, 0, 0
                       , nPort, oV6, 2 ) )
    { Log ( "SETUP: server would not start under P2PeerConFamily_IPv6" );
      WSACleanup ( ); return 2; }

    WSACleanup ( );

    std::printf ( "\n--- RESULT ---\n"
                  "  IPv4 family, %-11s : %s\n"
                  "  IPv6 family, %-11s : %s\n"
                  "  IPv6 family, %-11s : %s\n"
                , "127.0.0.1", oControl[0].bServed ? "served (expected)"
                                                   : "REFUSED"
                , "::1",       oV6[0].bServed      ? "served (expected)"
                                                   : "REFUSED"
                , "127.0.0.1", oV6[1].bConnected   ? "CONNECTED"
                                                   : "refused (expected)" );
    std::fflush ( stdout );

    if ( !oV6[0].bServed )
    {
      Log ( "FAIL: P2PeerConFamily_IPv6 would not serve ::1 - the transport "
            "does not speak IPv6" );
      return 1;
    }
    if ( oV6[1].bConnected )
    {
      Log ( "FAIL: a v6-ONLY service accepted a v4 connection - IPV6_V6ONLY "
            "was not set, so the family the operator asked for is not the one "
            "the socket has" );
      return 1;
    }

    Log ( "PASS: the v6 family served v6 and refused v4" );
    return 0;
}

// =========================================================================
//  Phase 2 - ONE SOCKET, BOTH FAMILIES
// =========================================================================
static int Dual ( short nPort )
{
    std::printf ( "=== p2p_ipv6 --dual (port %d) ===\n", (int)nPort );
    std::fflush ( stdout );

    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    if ( !HostHasIPv6 ( ) )
    {
      Log ( "SETUP: this host will not bind ::1" );
      WSACleanup ( );
      return 2;
    }

    //  Scope ANY, because DUAL cannot express a loopback scope and Listen()
    //  refuses the pair rather than picking one of the two loopbacks - refer
    //  ListenBindSockaddr(). :: with IPV6_V6ONLY off is the only bind that
    //  covers both, which is exactly what is being measured
    Probe oBoth[2] = { { AF_INET6, "::1",       false, false }
                     , { AF_INET,  "127.0.0.1", false, false } };
    if ( !ProbeService ( P2PeerConFamily_Dual, P2PeerConScope_Any, 0, 0
                       , nPort, oBoth, 2 ) )
    { Log ( "SETUP: server would not start under P2PeerConFamily_Dual" );
      WSACleanup ( ); return 2; }

    WSACleanup ( );

    std::printf ( "\n--- RESULT ---\n"
                  "  dual family, %-11s : %s\n"
                  "  dual family, %-11s : %s\n"
                , "::1",       oBoth[0].bServed ? "served (expected)" : "REFUSED"
                , "127.0.0.1", oBoth[1].bServed ? "served (expected)" : "REFUSED" );
    std::fflush ( stdout );

    if ( !oBoth[0].bServed )
    { Log ( "FAIL: the dual service refused IPv6" ); return 1; }
    if ( !oBoth[1].bServed )
    { Log ( "FAIL: the dual service refused IPv4 - IPV6_V6ONLY is still on, so "
            "it is a v6-only service wearing the dual name" );
      return 1; }

    Log ( "PASS: one socket served both families" );
    return 0;
}

// =========================================================================
//  Phase 3 - THE ALLOW-LIST IN TWO FAMILIES
// =========================================================================
static bool AddrOf ( int nFamily, const char *szText
                   , SOCKADDR_STORAGE &rAddr, int &rnLen )
{
    std::memset ( &rAddr, 0, sizeof(rAddr) );
    rnLen = 0;

    addrinfo  oHints;
    addrinfo *pResult = 0;
    std::memset ( &oHints, 0, sizeof(oHints) );
    oHints.ai_family = nFamily;
    oHints.ai_flags  = AI_NUMERICHOST;
    if ( getaddrinfo ( szText, 0, &oHints, &pResult ) != 0 || !pResult )
      return false;

    std::memcpy ( &rAddr, pResult->ai_addr, (size_t)pResult->ai_addrlen );
    rnLen = (int)pResult->ai_addrlen;
    freeaddrinfo ( pResult );
    return true;
}

static int V6Filter ( short nPort )
{
    std::printf ( "=== p2p_ipv6 --v6filter (port %d) ===\n", (int)nPort );
    std::fflush ( stdout );

    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    if ( !HostHasIPv6 ( ) )
    { Log ( "SETUP: this host will not bind ::1" ); WSACleanup(); return 2; }

    if ( !StartupP2Pmsg ( 16 ) )
    { Log ( "SETUP: StartupP2Pmsg() failed" ); WSACleanup(); return 2; }

    int nVerdict = 0;
    {
        Ipv6Hub oServer ( kServerAddr );
        oServer.RequireAuth ( false );      // see the transport phase above
        HANDLE hThread = oServer.SpawnHub ( );
        if ( !hThread )
        { Log ( "SETUP: SpawnHub() failed" ); CleanupP2Pmsg(); WSACleanup();
          return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc )
        { Log ( "SETUP: ServiceFactory failed" ); oServer.CloseHub ( );
          CleanupP2Pmsg(); WSACleanup(); return 2; }

        //  ONE service, configured and questioned before it is posted, then
        //  posted and connected to. p2p_listenscope's shape, and for its
        //  reason: the DECISION and the SOCKET must be measured on the same
        //  object or they are two facts about two configurations
        pSvc -> SetFamily      ( P2PeerConFamily_Dual );
        pSvc -> SetListenScope ( P2PeerConScope_Any );

        // 1. THE PARSER, before anything opens a socket. A rule that is not
        //    understood must be reported and must add NOTHING
        const bool bBitsRejected = !pSvc -> AllowAcceptFrom ( _T("::1/129")      );
        const bool bZoneRejected = !pSvc -> AllowAcceptFrom ( _T("fe80::1%eth0") );
        const bool bJunkRejected = !pSvc -> AllowAcceptFrom ( _T("gg::1")        );
        const bool bStillEmpty   = !pSvc -> HasAcceptSourceFilter ( );

        const bool bDocAccepted  =  pSvc -> AllowAcceptFrom ( _T("2001:db8::/32") );
        const bool bUlaAccepted  =  pSvc -> AllowAcceptFrom ( _T("fc00::/7")      );
        const bool bV4Accepted   =  pSvc -> AllowAcceptFrom ( _T("127.0.0.0/8")   );

        const bool bParser = bBitsRejected && bZoneRejected && bJunkRejected &&
                             bStillEmpty   && bDocAccepted  && bUlaAccepted  &&
                             bV4Accepted;

        // 2. THE DECISION, asked directly. A /32 admits inside and refuses
        //    outside, and neither family's rules reach into the other's space
        SOCKADDR_STORAGE oIn, oOut, oV4, oV6Loop, oV4Mapped;
        int              nIn = 0, nOut = 0, nV4 = 0, nV6Loop = 0, nV4Mapped = 0;
        const bool bParsed =
          AddrOf ( AF_INET6, "2001:db8::5", oIn,     nIn     ) &&
          AddrOf ( AF_INET6, "2001:db9::5", oOut,    nOut    ) &&
          AddrOf ( AF_INET,  "127.0.0.1",   oV4,     nV4     ) &&
          AddrOf ( AF_INET6, "::1",         oV6Loop, nV6Loop ) &&
          AddrOf ( AF_INET6, "::ffff:127.0.0.1", oV4Mapped, nV4Mapped );

        if ( !bParsed )
        { Log ( "SETUP: the harness could not parse its own addresses" );
          oServer.CloseHub ( ); WaitForSingleObject ( hThread, 3000 );
          CloseHandle ( hThread ); CleanupP2Pmsg(); WSACleanup(); return 2; }

        const bool bInAllowed =
          pSvc -> IsAcceptSourceAllowed ( (const sockaddr *)&oIn,  nIn  );
        const bool bOutRefused =
         !pSvc -> IsAcceptSourceAllowed ( (const sockaddr *)&oOut, nOut );
        const bool bV4Allowed =
          pSvc -> IsAcceptSourceAllowed ( (const sockaddr *)&oV4,  nV4  );
        //  ::1 is NOT on this list - "fc00::/7" does not cover it, "2001:db8::
        //  /32" does not, and no v4 rule can. A list of rules in one family
        //  refuses every source of the other, and that trap is worth pinning
        //  down rather than discovering
        const bool bV6LoopRefused =
         !pSvc -> IsAcceptSourceAllowed ( (const sockaddr *)&oV6Loop, nV6Loop );
        //  THE NORMALISATION, asked directly: ::ffff:127.0.0.1 must be read as
        //  127.0.0.1 and admitted by the v4 rule
        const bool bMapped =
          pSvc -> IsAcceptSourceAllowed ( (const sockaddr *)&oV4Mapped
                                        , nV4Mapped );

        const bool bDecision = bInAllowed && bOutRefused && bV4Allowed &&
                               bV6LoopRefused;

        //  Both caps OFF, so nothing but the allow-list can refuse anything
        pSvc -> SetMaxAccepted          ( 0 );
        pSvc -> SetMaxAcceptedPerSource ( 0 );
        pSvc -> SetLoginDeadline        ( 0 );
        oServer.PostP2PeerCon ( pSvc );
        Sleep ( 700 );

        Log ( "dual service listening on ANY; v4 and v6 rules, none covering ::1" );

        // 3. THE NORMALISATION, END TO END
        SOCKET sV4 = RawConnect ( AF_INET,  "127.0.0.1", nPort );
        SOCKET sV6 = RawConnect ( AF_INET6, "::1",       nPort );
        if ( sV4 == INVALID_SOCKET || sV6 == INVALID_SOCKET )
        {
          Log ( "SETUP: this host would not lend both loopback families" );
          RawClose ( sV4 ); RawClose ( sV6 );
          oServer.CloseHub ( ); WaitForSingleObject ( hThread, 3000 );
          CloseHandle ( hThread ); CleanupP2Pmsg(); WSACleanup(); return 2;
        }

        const bool bV6Closed = WasClosedByPeer ( sV6, 2000 );
        const bool bV4Up     = !WasClosedByPeer ( sV4, 1000 );
        RawClose ( sV4 ); RawClose ( sV6 );

        std::printf ( "\n--- RESULT ---\n"
                      "  malformed v6 prefixes rejected : %s\n"
                      "  ...and added nothing           : %s\n"
                      "  2001:db8::5 vs 2001:db8::/32   : %s\n"
                      "  2001:db9::5 vs 2001:db8::/32   : %s\n"
                      "  127.0.0.1   vs 127.0.0.0/8     : %s\n"
                      "  ::1         vs rules not it    : %s\n"
                      "  ::ffff:127.0.0.1 normalised    : %s\n"
                      "  dual socket, 127.0.0.1         : %s\n"
                      "  dual socket, ::1               : %s\n"
                    , ( bBitsRejected && bZoneRejected && bJunkRejected )
                                       ? "yes (expected)"    : "NO"
                    , bStillEmpty      ? "yes (expected)"    : "NO"
                    , bInAllowed       ? "allowed (expected)": "REFUSED"
                    , bOutRefused      ? "refused (expected)": "ALLOWED"
                    , bV4Allowed       ? "allowed (expected)": "REFUSED"
                    , bV6LoopRefused   ? "refused (expected)": "ALLOWED"
                    , bMapped          ? "allowed (expected)": "REFUSED"
                    , bV4Up            ? "served (expected)" : "CLOSED"
                    , bV6Closed        ? "closed (expected)" : "SERVED" );
        std::fflush ( stdout );

        if ( !bParser )
        { Log ( "FAIL: a malformed v6 prefix was accepted, or a well-formed "
                "one was not, so the filter is not the one the operator "
                "wrote" ); nVerdict = 1; }
        else if ( !bDecision )
        { Log ( "FAIL: IsAcceptSourceAllowed() answers the wrong thing for a "
                "v6 prefix, or lets one family's rules reach into the "
                "other's space" ); nVerdict = 1; }
        else if ( !bMapped )
        { Log ( "FAIL: ::ffff:127.0.0.1 was not read as 127.0.0.1, so an "
                "allow-list means different things on a v4 and a dual "
                "socket" ); nVerdict = 1; }
        else if ( !bV4Up )
        { Log ( "INCONCLUSIVE: the PERMITTED v4 source was closed by the dual "
                "service, so the refusal below proves nothing" );
          nVerdict = 3; }
        else if ( !bV6Closed )
        { Log ( "FAIL: a v6 source was served by a service no rule of which "
                "covers it" ); nVerdict = 1; }
        else
          Log ( "PASS: the allow-list means one thing in both families, and a "
                "v4-mapped peer is a v4 peer" );

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
    short nPort     = 7850;
    bool  bV6Only   = false;
    bool  bDual     = false;
    bool  bV6Filter = false;

    for ( int i = 1; i < argc; ++i )
    {
      if      ( std::strcmp ( argv[i], "--v6-only"  ) == 0 ) bV6Only   = true;
      else if ( std::strcmp ( argv[i], "--dual"     ) == 0 ) bDual     = true;
      else if ( std::strcmp ( argv[i], "--v6filter" ) == 0 ) bV6Filter = true;
      else
      {
        const int n = std::atoi ( argv[i] );
        if ( n > 100 && n < 65536 ) nPort = (short)n;
      }
    }

    //  One mode, one verdict, one exit code - p2p_acceptcap's rule, and the
    //  reason its phases became separate ctest targets off one source
    if ( bV6Filter ) return V6Filter ( nPort );
    if ( bDual     ) return Dual     ( nPort );
    if ( bV6Only   ) return V6Only   ( nPort );

    std::printf ( "usage: p2p_ipv6 [port] --v6-only | --dual | --v6filter\n" );
    return 2;
}
