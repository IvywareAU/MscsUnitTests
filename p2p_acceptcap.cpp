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
// p2p_acceptcap.cpp - SECURITY GATE TEST: is there any bound on what an
// UNAUTHENTICATED peer can hold open?
//
// BACKGROUND - the gap this closes. Every other security gate in this suite
// asks a question about a peer that has spoken: is its login real, is its
// source bound, can the hub in the middle read the body. This one asks about a
// peer that says NOTHING, and until 2026-08-16 the answer was that it could
// have whatever it liked:
//
//   * NOTHING COUNTED ACCEPTED CONNECTIONS. A P2PeerCon in SERVICE mode
//     accepted, spawned, re-armed and accepted again with no notion of how many
//     children were live. The bound was the descriptor table.
//   * NOTHING TIMED A LOGIN OUT. The timer to do it has been complete since the
//     import - On_PITimer() throws "Login timed out" on expiry, OnLogin(),
//     OnClose() and ~P2PeerCon() all cancel it - but the single line that ARMED
//     it sat commented out in P2PeerTarget::On_ConAccept(). So a peer could
//     connect, never log in, and sit there holding a socket forever.
//
// Both are spent BEFORE a login is attempted, which is why none of the login
// work touched them: RequireAuth(true) decides who may speak, and neither of
// these is about speaking.
//
// WHAT IT DOES - two phases against one server, using RAW sockets rather than
// hubs. Raw is the point: the adversary being modelled does not run this
// library and will not complete a handshake, so the test must not either.
//
//   Phase 1 (THE CAP): the service is set to SetMaxAccepted(2) with the login
//   deadline OFF, so nothing else can close anything. Three raw sockets
//   connect. The first two MUST stay up - that is the positive control, and
//   without it a cap that refuses everything would pass. The third MUST be
//   closed by the server.
//
//   Phase 2 (THE DEADLINE): the cap is lifted and SetLoginDeadline(1500) set.
//   One raw socket connects and sends nothing at all. It MUST be closed. A
//   control socket is then opened and checked to still be up inside the same
//   window, so "the server closed it" is distinguishable from "the server
//   stopped serving".
//
//   Phase 3 (THE SOURCE SHARE, --source-only): the paragraph that used to sit
//   here said the cap "is per SERVICE connection, not per host and not per
//   source address: one peer opening 2 connections and two peers opening one
//   each are the same thing to it", and that bounding by origin "needs an
//   accounting key this layer does not have - the address is not known until
//   the login that has not happened."
//
//   Half of that was right and half of it was a wrong turn. The P2P ADDRESS is
//   indeed unknown until a login that a peer holding slots has no intention of
//   performing - but the SOURCE IP is known at accept, from the kernel, about a
//   peer that has said nothing. ProductionPlan.md Stage 4 step 11 is that key,
//   and this phase is its exit criterion: against SetMaxAcceptedPerSource(2)
//   with the service cap set generously at 16, two connections from 127.0.0.2
//   are admitted, a third from 127.0.0.2 is refused, and one from 127.0.0.3
//   still gets in.
//
//   The LAST of those four is the whole test. Without it, a bound that simply
//   refused the third connection from anywhere would pass - which is the
//   service cap this file already measures, wearing a different name.
//
// VERDICT = process EXIT CODE:
//   0  PASS   the 3rd connection refused, the silent one dropped, controls up
//   1  FAIL   an over-cap connection was served, or a silent peer was not
//             dropped
//   2  SETUP  startup / listen failure (test inconclusive)
//   3  INCONCLUSIVE a control connection died, so the refusals prove nothing

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kServerAddr = L"Cap.Server";
static const P2PaddrSTR kDomain     = L"Cap.*";

static void Log ( const char *msg )
{
    std::printf ( "[acceptcap] %s\n", msg );
    std::fflush ( stdout );
}

// ---------------------------------------------------------------------------
// A raw TCP peer. Connects, and never says anything the library would
// recognise - which is the whole point.
// ---------------------------------------------------------------------------
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

//  The same, from a NOMINATED local address.
//  NOTES: 127.0.0.0/8 is entirely loopback on both platforms, so 127.0.0.2 and
//         127.0.0.3 are two distinct sources that need no second machine, no
//         second NIC and no privileges. Measured on both before this test was
//         written to depend on it: bind() succeeds and the server's
//         getpeername() reports the bound address back
//       : Port 0 - the source PORT must be left to the kernel. It differs on
//         every connection by design, which is exactly why it is not part of
//         the accounting key
//       : Returns INVALID_SOCKET for a bind failure the same as for a connect
//         failure, and the caller reports either as SETUP rather than FAIL. A
//         host that will not lend a second loopback address makes this test
//         inconclusive; it does not make the bound broken
static SOCKET RawConnectFrom ( const char *szSource, short nPort )
{
    SOCKET s = socket ( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    if ( s == INVALID_SOCKET ) return INVALID_SOCKET;

    sockaddr_in oLocal;
    std::memset ( &oLocal, 0, sizeof(oLocal) );
    oLocal.sin_family      = AF_INET;
    oLocal.sin_port        = 0;
    oLocal.sin_addr.s_addr = inet_addr ( szSource );
    if ( bind ( s, (sockaddr *)&oLocal, sizeof(oLocal) ) == SOCKET_ERROR )
    { closesocket ( s ); return INVALID_SOCKET; }

    sockaddr_in oAddr;
    std::memset ( &oAddr, 0, sizeof(oAddr) );
    oAddr.sin_family      = AF_INET;
    oAddr.sin_port        = htons ( (u_short)nPort );
    oAddr.sin_addr.s_addr = inet_addr ( "127.0.0.1" );

    if ( connect ( s, (sockaddr *)&oAddr, sizeof(oAddr) ) == SOCKET_ERROR )
    { closesocket ( s ); return INVALID_SOCKET; }

    return s;
}

//  Has the far end closed this socket?
//  NOTES: Blocks up to dwWaitMs. recv() returning 0 is a graceful close and
//         SOCKET_ERROR/WSAECONNRESET an abortive one; both mean the server let
//         go, and which one it is depends on timing rather than on policy
//       : A timeout means the connection is STILL UP, which is the answer the
//         control cases want
//  Has the far end closed this socket? Portability is the whole difficulty
//  here, and two obvious answers are both wrong on one platform or the other:
//
//    * SO_RCVTIMEO takes a DWORD of MILLISECONDS on Winsock and a struct
//      timeval on POSIX. The Windows form on Linux sets a nonsense timeout and
//      the recv never returns - the test hung until ctest killed it at 120s,
//      having passed on Windows (found 2026-08-16).
//    * select()/FD_SET cannot be used at all: on Linux the Platform shim makes
//      SOCKET a P2PHandle*, not a descriptor, so it is not an fd_set member.
//
//  So: non-blocking (ioctlsocket FIONBIO, which the shim does implement) and
//  poll. The decision keys ONLY on recv() returning 0, which means orderly
//  close on both platforms and needs no error code - and an error code is
//  exactly what is not portable here, because the shim maps EAGAIN to
//  ERROR_SHARING_VIOLATION rather than to WSAEWOULDBLOCK.
//
//  recv() returning 0 is an orderly close on both platforms and needs no error
//  code. An ABORTIVE close does not: it surfaces as SOCKET_ERROR, and telling
//  that apart from "nothing to read yet" is the one place an error code is
//  unavoidable. Both values are knowable:
//
//    Windows  WSAEWOULDBLOCK          (10035)
//    Linux    ERROR_SHARING_VIOLATION (32) - the shim maps EAGAIN through
//             win32_from_errno (p2ptypes.h), which does NOT produce
//             WSAEWOULDBLOCK, so testing only the Winsock value silently
//             treats every Linux poll as a failure
//
//  Accepting both is safe in both directions: a Windows socket recv never
//  yields 32, and a Linux one never yields 10035. Treating an unrecognised
//  error as CLOSED is right - a reset peer is gone, and reading it as "still
//  up" made this test report a working deadline as a failure (Windows,
//  2026-08-16) because the drop arrives there as a reset rather than a FIN.
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

// =========================================================================
class CapHub : public P2PeerHub
{
public:
    CapHub ( P2PaddrSTR strAddr ) : P2PeerHub ( strAddr ) { }
    virtual ~CapHub ( ) { }
};

// =========================================================================
//  --rawonly: the CONTROL for this whole test. Stands the same server up with
//  NEITHER bound armed, runs the same raw-socket dance, and shuts down. It
//  exists because the first armed run of the login deadline died during
//  teardown AFTER printing its own PASS, and "my new bound crashes the
//  shutdown" and "a raw socket that never speaks P2P crashes the shutdown"
//  are different defects with the same symptom. Run it when this test dies
//  late: if the control dies too, the bounds are not the cause.
//  --cap=N / --deadline=N set the two bounds for the control run, so which of
//  them is responsible for a late death can be established in one run each
//  rather than by rebuilding.
static int RawOnly ( short nPort, long xCap, P2Pmsecs_t uDeadline )
{
    std::printf ( "=== p2p_acceptcap --rawonly (control: cap=%ld deadline=%ums) ===\n",
                  xCap, (unsigned)uDeadline );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );
    {
        CapHub oServer ( kServerAddr );
        //  RequireAuth(false). This binary measures two RESOURCE bounds - the
        //  accept cap, and the deadline on a peer that connects and then says
        //  nothing - and the header is explicit that neither of them is a
        //  who-may-speak question. Requiring auth (the default since Stage 3
        //  step 8) would drop the silent peer for a second reason and make the
        //  deadline unmeasurable.
        oServer.RequireAuth ( false );
        HANDLE hThread = oServer.SpawnHub ( );
        if ( !hThread ) { Log ( "SETUP: SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        pSvc -> SetMaxAccepted   ( xCap );
        pSvc -> SetLoginDeadline ( uDeadline );
        oServer.PostP2PeerCon ( pSvc );
        Sleep ( 500 );

        SOCKET a = RawConnect ( nPort ); Sleep ( 400 );
        SOCKET b = RawConnect ( nPort ); Sleep ( 400 );
        SOCKET c = RawConnect ( nPort ); Sleep ( 400 );
        std::printf ( "[acceptcap] control: three raw sockets connected\n" );
        std::fflush ( stdout );
        RawClose ( a ); RawClose ( b ); RawClose ( c );
        Sleep ( 600 );

        Log ( "control shutdown begin" );
        oServer.CloseHub ( );
        WaitForSingleObject ( hThread, 3000 );
        CloseHandle ( hThread );
    }
    CleanupP2Pmsg ( );
    WSACleanup ( );
    std::printf ( "control reached the end cleanly (exit=0).\n" );
    std::fflush ( stdout );
    return 0;
}

// =========================================================================
//  Phase 3, standalone: the per-source share (ProductionPlan.md Stage 4
//  step 11).  Its own function rather than a third block inside main(), for
//  the reason the CMake banner gives for p2p_logindeadline having its own
//  target: one test, one verdict, one exit code.  A phase spliced after
//  phase 2 would print a second RESULT line underneath the first.
static int SourceBound ( short nPort )
{
    std::printf ( "=== p2p_srcbound - one source cannot take the service ===\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::printf ( "Asserting: a bound per SOURCE, not merely per service -\n"
                  "           127.0.0.2 hits its share while 127.0.0.3 gets in.\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    int nExit = 2;
    {
        CapHub oServer ( kServerAddr );
        oServer.RequireAuth ( false );   // a resource bound, not a who-may-speak one
        HANDLE hServerThread = oServer.SpawnHub ( );
        if ( !hServerThread ) { Log ( "SETUP: server SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }

        //  The service cap is set GENEROUSLY rather than off.  Off would prove
        //  the same thing, but 16 proves it while the service is demonstrably
        //  not full: at the moment the third connection is refused there are
        //  two live out of sixteen, so "at capacity" cannot be the reason and
        //  the refusal has to be the per-source share
        pSvc -> SetMaxAccepted          ( 16 );
        pSvc -> SetMaxAcceptedPerSource ( 2 );
        pSvc -> SetLoginDeadline        ( 0 );   // nothing else may close anything
        oServer.PostP2PeerCon ( pSvc );
        Log ( "server listening; SetMaxAccepted(16), SetMaxAcceptedPerSource(2)" );
        Sleep ( 500 );

        Log ( "--- two from 127.0.0.2, against a share of two ---" );
        SOCKET a1 = RawConnectFrom ( "127.0.0.2", nPort ); Sleep ( 400 );
        SOCKET a2 = RawConnectFrom ( "127.0.0.2", nPort ); Sleep ( 400 );
        if ( a1 == INVALID_SOCKET || a2 == INVALID_SOCKET )
        {
            std::printf (
              "\nRESULT: SETUP - could not open two connections from 127.0.0.2.\n"
              "  Either bind() to a second loopback address is refused on this\n"
              "  host, or the service is not listening. 127.0.0.0/8 is loopback\n"
              "  in its entirety on both platforms this tree builds for, and both\n"
              "  were measured before this test was written to rely on it - so a\n"
              "  failure here is about the host, not about the bound.\n" );
            RawClose ( a1 ); RawClose ( a2 );
            oServer.CloseHub ( );
            WaitForSingleObject ( hServerThread, 3000 );
            CloseHandle ( hServerThread );
            CleanupP2Pmsg ( ); WSACleanup ( );
            return 2;
        }

        //  Third from the SAME source: expected to complete its handshake into
        //  the backlog and then be closed at accept, exactly as the service cap
        //  refuses in phase 1
        Log ( "--- a third from 127.0.0.2: must be refused ---" );
        SOCKET a3 = RawConnectFrom ( "127.0.0.2", nPort ); Sleep ( 400 );
        const bool b3Closed = WasClosedByPeer ( a3, 4000 );

        //  A DIFFERENT source, opened while the first is at its share.  This is
        //  the assertion the whole test exists for
        Log ( "--- and one from 127.0.0.3: must still get in ---" );
        SOCKET b1 = RawConnectFrom ( "127.0.0.3", nPort ); Sleep ( 400 );
        const bool bOtherConnected = ( b1 != INVALID_SOCKET );
        const bool bOtherUp = bOtherConnected && !WasClosedByPeer ( b1, 1500 );

        const bool b1Up = !WasClosedByPeer ( a1, 1000 );
        const bool b2Up = !WasClosedByPeer ( a2, 1000 );

        std::printf ( "[acceptcap] .2 first=%s second=%s third=%s | .3 =%s\n",
                      b1Up ? "up" : "GONE", b2Up ? "up" : "GONE",
                      b3Closed ? "closed" : "SERVED",
                      bOtherUp        ? "up"
                    : bOtherConnected ? "CONNECTED THEN CLOSED"
                                      : "CONNECT REFUSED" );
        std::fflush ( stdout );

        RawClose ( a1 ); RawClose ( a2 ); RawClose ( a3 ); RawClose ( b1 );
        Sleep ( 1200 );                   // let the service reap the slots

        //  THE SLOT MUST COME BACK, and nothing above would notice if it did
        //  not.  A per-source tally that only counts up is indistinguishable
        //  from a working one for the length of a test and fatal in a
        //  deployment: the service admits a source's share, those peers come
        //  and go, and some hours later that address is refused permanently
        //  while every count an operator can read says the service is nearly
        //  empty.
        //
        //  A THIRD ADDRESS AND AN ARMED DEADLINE, rather than simply re-dialling
        //  127.0.0.2.  The reason was a defect this test FOUND and did not
        //  close - ProductionPlan.md F-S4-1: a peer that connected, said
        //  nothing and DISCONNECTED was never reaped on Windows.  Measured
        //  here, three peers closed and GetAcceptedCount() stayed at 3
        //  indefinitely with the hub still listing all four connections.
        //  F-S4-1 IS CLOSED (2026-08-20) and p2p_conreap is its gate, so
        //  re-dialling 127.0.0.2 would now work - but this phase is left as it
        //  is on purpose.  What it proves is that the per-source SHARE is
        //  released and re-taken, and proving that through a reaping path
        //  which is itself under test elsewhere would couple two verdicts:
        //  a red here would no longer say whether the share leaked or the
        //  close stopped being seen.  The deadline is the independent path.
        //
        //  The login deadline IS a reaping path that works, so arm it and use
        //  it: 127.0.0.4 takes its whole share, the deadline drops both, and
        //  the share must then be available again - and must still be a share.
        //  Children inherit the deadline AT SPAWN, so setting it now cannot
        //  disturb anything already accepted above.
        //  3000ms, not the 1500 phase 2 uses, and the margin is the point.
        //  bTookShare below has to observe d1 ALIVE, so every millisecond spent
        //  dialling and polling before that observation is margin spent - and
        //  under ASan on Linux that is not the same number as on Windows.  At
        //  1200ms this read as "127.0.0.4 never got its share" on Linux while
        //  passing on Windows: the deadline was firing inside the very poll
        //  that was checking the connection was still up
        pSvc -> SetLoginDeadline ( 3000 );
        Sleep ( 200 );

        Log ( "--- 127.0.0.4 takes its share, is timed out, and comes back ---" );
        SOCKET d1 = RawConnectFrom ( "127.0.0.4", nPort ); Sleep ( 200 );
        SOCKET d2 = RawConnectFrom ( "127.0.0.4", nPort ); Sleep ( 200 );
        const bool bTookShare = ( d1 != INVALID_SOCKET && d2 != INVALID_SOCKET ) &&
                                !WasClosedByPeer ( d1, 200 );

        //  Generous against 3000ms: the timer fires on the pump, and a loaded
        //  machine - or a sanitised build - may take a moment to deliver it
        const bool bTimedOut = WasClosedByPeer ( d1, 12000 ) &&
                               WasClosedByPeer ( d2, 6000 );
        RawClose ( d1 ); RawClose ( d2 );
        Sleep ( 800 );                    // let the drops settle

        SOCKET d3 = RawConnectFrom ( "127.0.0.4", nPort ); Sleep ( 300 );
        SOCKET d4 = RawConnectFrom ( "127.0.0.4", nPort ); Sleep ( 300 );
        const bool bReadmitted = ( d3 != INVALID_SOCKET && d4 != INVALID_SOCKET ) &&
                                 !WasClosedByPeer ( d3, 400 );
        //  And it must STILL be a bound.  A release that overshot - decrementing
        //  more than it added, or erasing the entry on the first release of
        //  several - would readmit the two above AND everything after them
        SOCKET d5 = RawConnectFrom ( "127.0.0.4", nPort ); Sleep ( 300 );
        const bool bStillBound = WasClosedByPeer ( d5, 4000 );
        RawClose ( d3 ); RawClose ( d4 ); RawClose ( d5 );

        std::printf ( "[acceptcap] .4 share=%s timedout=%s readmitted=%s stillbound=%s\n",
                      bTookShare  ? "taken"   : "REFUSED",
                      bTimedOut   ? "dropped" : "STILL UP",
                      bReadmitted ? "yes"     : "NO",
                      bStillBound ? "yes"     : "NO" );
        std::fflush ( stdout );

        if ( !b1Up || !b2Up )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - a connection INSIDE the share was dropped.\n"
              "  The share is supposed to admit two from 127.0.0.2 and refuse the\n"
              "  third; if it refuses everything then the third being closed proves\n"
              "  nothing. Check that SourceAtCapacity() reads the SERVICE's own\n"
              "  m_xMaxAcceptedPerSource, and that ~P2PeerCon() gives the slot back\n"
              "  through P2PeerConSourceTally::Sub().\n" );
            nExit = 3;
        }
        else if ( !b3Closed )
        {
            std::printf (
              "\nRESULT: FAIL - THE PER-SOURCE SHARE DOES NOT BIND.\n"
              "  Two connections from 127.0.0.2 were already live against\n"
              "  SetMaxAcceptedPerSource(2) and a third from the same address was\n"
              "  served anyway. The service cap alone cannot tell one peer taking\n"
              "  1024 slots apart from 1024 peers taking one each, which is the\n"
              "  hole Stage 4 step 11 closes. Check P2PeerConWsa::AcceptSourceKey()\n"
              "  returns non-zero (getpeername on the ACCEPTED socket, before it is\n"
              "  handed to the child), and that AcceptSpawn() refuses on\n"
              "  SourceAtCapacity() as well as AcceptAtCapacity().\n" );
            nExit = 1;
        }
        else if ( !bOtherUp )
        {
            std::printf (
              "\nRESULT: FAIL - IT BOUND THE SERVICE, NOT THE SOURCE (%s).\n"
              "  The third connection from 127.0.0.2 was refused, which looks\n"
              "  right - but a connection from 127.0.0.3 was refused too, with\n"
              "  only two of sixteen service slots taken. A bound that refuses\n"
              "  every source once ANY source is at its share is the service cap\n"
              "  with extra steps, and it is worse than the service cap: one peer\n"
              "  could then deny the service to everybody else by taking its own\n"
              "  share and then doing nothing at all.\n"
              "  Check the tally is keyed per source - P2PeerConSourceTally in\n"
              "  P2PeerCon.cpp - and that AcceptSourceKey() is not returning the\n"
              "  same value for both addresses.\n",
              bOtherConnected ? "connected then closed" : "connect refused" );
            nExit = 1;
        }
        else if ( !bTookShare || !bTimedOut )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the release could not be measured (%s).\n"
              "  127.0.0.4 was meant to take its share of two and then be reaped\n"
              "  by SetLoginDeadline(1200), so that the share could be shown to\n"
              "  come back. The share above binds either way - that verdict is\n"
              "  not in doubt - but whether the slot is ever RELEASED is then\n"
              "  untested, and an unreleased slot is a permanent refusal.\n"
              "  If the deadline is what failed, p2p_logindeadline measures it on\n"
              "  its own and will say so more precisely.\n",
              !bTookShare ? "it never got its share" : "the deadline never fired" );
            nExit = 3;
        }
        else if ( !bReadmitted )
        {
            std::printf (
              "\nRESULT: FAIL - THE SHARE IS NEVER GIVEN BACK.\n"
              "  127.0.0.4 took its share of two, both were dropped by the login\n"
              "  deadline, and it was still refused afterwards. A tally that only\n"
              "  counts up bounds a source PERMANENTLY at its first burst, which\n"
              "  no operator will read as a bound: the service reports itself\n"
              "  nearly empty while one address can never reconnect.\n"
              "  The release is in ~P2PeerCon(), beside the m_pxAccepted one and\n"
              "  for the same reason - a connection holds its slot for exactly as\n"
              "  long as the object exists, so no close path can forget it. Check\n"
              "  m_xAcceptSource is still set there, and that\n"
              "  P2PeerConSourceTally::Sub() erases the entry at zero.\n" );
            nExit = 1;
        }
        else if ( !bStillBound )
        {
            std::printf (
              "\nRESULT: FAIL - THE RELEASE OVERSHOT.\n"
              "  127.0.0.4 was readmitted after its two were reaped, which is\n"
              "  right - and then a THIRD was admitted too, against a share of\n"
              "  two. The tally is giving back more than it took, so a source that\n"
              "  churns connections raises its own ceiling and the bound decays to\n"
              "  nothing under exactly the traffic it exists to stop.\n"
              "  Check P2PeerConSourceTally::Sub() only erases at zero, and that\n"
              "  ~P2PeerCon() clears m_xAcceptSource so a second destruction of\n"
              "  the same object cannot decrement twice.\n" );
            nExit = 1;
        }
        else
        {
            std::printf (
              "\nRESULT: PASS - the per-source share binds, binds per source, and\n"
              "  is given back.\n"
              "  Against SetMaxAcceptedPerSource(2) with the service cap at 16:\n"
              "  two connections from 127.0.0.2 admitted, the third from that same\n"
              "  address closed at accept, and a connection from 127.0.0.3 served\n"
              "  while it was refused. So the refusal was about the ORIGIN and not\n"
              "  about the service, which had fourteen slots free throughout.\n"
              "  Then 127.0.0.4 took its own share, was reaped by the login\n"
              "  deadline, was readmitted to its full share afterwards - and was\n"
              "  refused at the third again. So the slots are released, released\n"
              "  exactly once each, and the bound survives the churn.\n" );
            nExit = 0;
        }

        Log ( "shutdown begin" );
        oServer.CloseHub ( );
        WaitForSingleObject ( hServerThread, 3000 );
        CloseHandle ( hServerThread );
    }

    CleanupP2Pmsg ( );
    WSACleanup ( );
    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    short nPort = ( argc >= 2 ) ? (short)atoi ( argv[1] ) : 7826;

    //  Which half to run. They remain separate ctest entries -- one test, one
    //  executable, verdict = exit code -- but they are no longer unequally
    //  supported. As of ProductionPlan.md Stage 2 step 6 the DEADLINE holds on
    //  both platforms, and p2p_logindeadline is registered without an if(WIN32).
    //
    //  What had made it Windows-only was never the deadline logic, which was
    //  correct all along. The Linux IOCP shim looked the completion key up from
    //  the fd AT COMPLETION TIME, while closesocket() erases that association
    //  before the cancellations it triggers complete. So dropping a timed-out
    //  peer delivered an aborted completion carrying key 0, the service read an
    //  unattributable completion as a failure of the LISTENER, and one silent
    //  peer took the whole listener down. The key is now bound at submission --
    //  OVERLAPPED::_p2p_key, Platform/p2piocp.h, which is where the reasoning
    //  and the Windows semantics it reproduces are written down.
    bool bRunCap = true, bRunDeadline = true;
    {
        bool       bRawOnly  = false;
        long       xCap      = 0;
        P2Pmsecs_t uDeadline = 0;
        for ( int i = 1; i < argc; i++ )
        {
            if ( std::strcmp ( argv[i], "--rawonly" ) == 0 ) bRawOnly = true;
            //  --source-only runs phase 3 and NOTHING else, and is the only
            //  way to reach it.  The two established entries are therefore
            //  unchanged by its arrival, which is deliberate: a new phase that
            //  altered what p2p_acceptcap and p2p_logindeadline measure would
            //  make every earlier STATUS line in the CMake banner a claim about
            //  a test that no longer runs the same way
            else if ( std::strcmp ( argv[i], "--source-only" ) == 0 )
                return SourceBound ( nPort );
            else if ( std::strcmp ( argv[i], "--cap-only" ) == 0 )
                bRunDeadline = false;
            else if ( std::strcmp ( argv[i], "--deadline-only" ) == 0 )
                bRunCap = false;
            else if ( std::strncmp ( argv[i], "--cap=", 6 ) == 0 )
                xCap = atol ( argv[i] + 6 );
            else if ( std::strncmp ( argv[i], "--deadline=", 11 ) == 0 )
                uDeadline = (P2Pmsecs_t)atol ( argv[i] + 11 );
        }
        if ( bRawOnly ) return RawOnly ( nPort, xCap, uDeadline );
    }

    std::printf ( "=== p2p_acceptcap - accept cap and login deadline gate ===\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::printf ( "Asserting: an unauthenticated peer cannot hold unlimited\n"
                  "           connections, nor one it never logs in on.\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    int nExit = 2;
    {
        CapHub oServer ( kServerAddr );
        oServer.RequireAuth ( false );  // see the accept-cap mode above
        HANDLE hServerThread = oServer.SpawnHub ( );
        if ( !hServerThread ) { Log ( "SETUP: server SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }

        // ---- Phase 1 settings: cap of 2, deadline OFF ---------------------
        // NOTES: The deadline is turned off so that a connection which goes
        //        away can only have gone away because of the cap. With both
        //        armed, phase 1 would be measuring whichever fired first
        pSvc -> SetMaxAccepted   ( bRunCap ? 2 : 0 );
        pSvc -> SetLoginDeadline ( 0 );
        oServer.PostP2PeerCon ( pSvc );
        Log ( bRunCap ? "server listening; SetMaxAccepted(2), login deadline off"
                      : "server listening; cap phase not selected" );
        Sleep ( 500 );

        bool bCapHeld = true;      // vacuously true when the phase is skipped
        if ( bRunCap )
        {
        // ---- Phase 1: the cap --------------------------------------------
        Log ( "--- phase 1: three raw connections against a cap of two ---" );
        SOCKET s1 = RawConnect ( nPort ); Sleep ( 400 );
        SOCKET s2 = RawConnect ( nPort ); Sleep ( 400 );
        SOCKET s3 = RawConnect ( nPort ); Sleep ( 400 );

        if ( s1 == INVALID_SOCKET || s2 == INVALID_SOCKET )
        {
            Log ( "SETUP: the first two connections did not even connect" );
            oServer.CloseHub ( );
            WaitForSingleObject ( hServerThread, 3000 );
            CloseHandle ( hServerThread );
            CleanupP2Pmsg ( ); WSACleanup ( );
            return 2;
        }

        // The third is EXPECTED to connect: the kernel completes the handshake
        // into the backlog and the refusal happens when the service accepts it.
        // A refused peer therefore sees a connection that opens and then goes,
        // which is what "closed rather than left pending" means in
        // P2PeerConWsa::AcceptSpawn()
        const bool b3Closed = WasClosedByPeer ( s3, 4000 );
        const bool b1Up     = !WasClosedByPeer ( s1, 1000 );
        const bool b2Up     = !WasClosedByPeer ( s2, 1000 );

        std::printf ( "[acceptcap] first=%s second=%s third=%s\n",
                      b1Up ? "up" : "GONE", b2Up ? "up" : "GONE",
                      b3Closed ? "closed" : "SERVED" );
        std::fflush ( stdout );

        RawClose ( s1 ); RawClose ( s2 ); RawClose ( s3 );
        Sleep ( 600 );                       // let the service reap the slots

        if ( !b1Up || !b2Up )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - a connection INSIDE the cap was dropped.\n"
              "  The cap is supposed to admit the first two and refuse the third;\n"
              "  if it refuses everything then the third being closed proves\n"
              "  nothing. Check that AcceptAtCapacity() reads the SERVICE's own\n"
              "  m_xMaxAccepted and that the counter is decremented in\n"
              "  ~P2PeerCon().\n" );
            nExit = 3;
            bCapHeld = false;
        }
        else if ( !b3Closed )
        {
            std::printf (
              "\nRESULT: FAIL - THE CAP DOES NOT BIND.\n"
              "  Two connections were already live against SetMaxAccepted(2) and\n"
              "  the third was served anyway. Nothing then bounds what an\n"
              "  unauthenticated peer can hold open, which is the state this\n"
              "  tree was in before 2026-08-16: the limit was the descriptor\n"
              "  table. Check P2PeerConWsa::AcceptSpawn() refuses before it\n"
              "  allocates, and that the base AcceptSpawn() increments.\n" );
            nExit = 1;
            bCapHeld = false;
        }
        else
            Log ( "cap holds - two admitted, third closed" );
        }   // if ( bRunCap )

        if ( bCapHeld && !bRunDeadline )
        {
            std::printf (
              "\nRESULT: PASS - the accept cap binds.\n"
              "  Against SetMaxAccepted(2): two connections admitted and the\n"
              "  third closed at accept, with the two inside the cap still up.\n"
              "  The login deadline is NOT covered by this run - it is a\n"
              "  separate ctest entry (p2p_logindeadline), which as of Stage 2\n"
              "  step 6 runs on BOTH platforms. DEF_P2PeerConLogin is still 0:\n"
              "  the cascade that forced that default is fixed, but changing\n"
              "  the default is Stage 3's decision, not this test's.\n" );
            nExit = 0;
        }
        else if ( bCapHeld )
        {
            // ---- Phase 2: the login deadline -------------------------------
            // The service is re-configured: children inherit these values as
            // they are spawned, so a change here reaches the NEXT connection
            Log ( "--- phase 2: a peer that connects and never logs in ---" );
            pSvc -> SetMaxAccepted   ( 0 );        // unbound, so the cap is out
            pSvc -> SetLoginDeadline ( 1500 );     // and the deadline is in
            Sleep ( 200 );

            SOCKET sSilent = RawConnect ( nPort );
            if ( sSilent == INVALID_SOCKET )
            {
                Log ( "SETUP: the silent peer could not connect" );
                nExit = 2;
            }
            else
            {
                // Generous against 1500ms: the timer fires on the pump, and a
                // loaded machine may take a moment to deliver it. What must not
                // happen is that it never fires at all
                const bool bDropped = WasClosedByPeer ( sSilent, 8000 );
                RawClose ( sSilent );

                // Liveness. A server that has fallen over also closes sockets,
                // and "dropped" and "dead" would otherwise be the same reading.
                //
                // The deadline is turned OFF FIRST, so this control is not
                // racing the very mechanism it exists to be independent of.
                // Leaving it on made the control's survival mean only "700ms
                // elapsed before 1500ms did", which held on Windows and did
                // not on Linux - a fragile control that reports INCONCLUSIVE
                // on a working tree is worse than no control at all
                pSvc -> SetLoginDeadline ( 0 );
                Sleep ( 200 );

                SOCKET sCtrl = RawConnect ( nPort );
                const bool bCtrlConnected = ( sCtrl != INVALID_SOCKET );
                const bool bCtrlUp = bCtrlConnected &&
                                     !WasClosedByPeer ( sCtrl, 700 );
                RawClose ( sCtrl );

                std::printf ( "[acceptcap] silent=%s control=%s\n",
                              bDropped ? "dropped" : "STILL UP",
                              bCtrlUp        ? "up"
                            : bCtrlConnected ? "CONNECTED THEN CLOSED"
                                             : "CONNECT REFUSED" );
                std::fflush ( stdout );

                if ( !bDropped )
                {
                    std::printf (
                      "\nRESULT: FAIL - A PEER THAT NEVER LOGS IN IS NEVER DROPPED.\n"
                      "  SetLoginDeadline(1500) was set on the service and a raw\n"
                      "  socket that sent nothing was still connected many seconds\n"
                      "  later. The timer itself has always worked; what was\n"
                      "  missing was the call that arms it. Check\n"
                      "  P2PeerTarget::On_ConAccept() calls ArmLoginDeadline() on\n"
                      "  the SPAWNED connection, after it is posted.\n" );
                    nExit = 1;
                }
                else if ( !bCtrlUp )
                {
                    std::printf (
                      "\nRESULT: INCONCLUSIVE - the silent peer was dropped, but a\n"
                      "  fresh connection opened straight afterwards did not survive\n"
                      "  either (%s). The service stopped serving, so the drop above\n"
                      "  is not evidence of a deadline.\n"
                      "\n"
                      "  THIS IS A REGRESSION OF THE STAGE 2 STEP 6 FIX, most likely.\n"
                      "  This exact shape - silent peer dropped, listener then dead -\n"
                      "  was the Linux accept cascade, and it was fixed by binding the\n"
                      "  IOCP completion key at SUBMISSION instead of looking it up\n"
                      "  from the fd at completion. closesocket() erases the fd -> key\n"
                      "  association before the cancellations it triggers complete, so\n"
                      "  the lookup returned 0 and an aborted completion arrived\n"
                      "  unattributable; the service read that as a failure of the\n"
                      "  LISTENER and dropped itself. Check OVERLAPPED::_p2p_key in\n"
                      "  Platform/p2piocp.h and its use in GetQueuedCompletionStatus.\n"
                      "  Reverting that one line reproduces this message exactly.\n",
                      bCtrlConnected ? "connected then closed" : "connect refused" );
                    nExit = 3;
                }
                else
                {
                    std::printf (
                      "\nRESULT: PASS - the login deadline binds.\n"
                      "  Against SetLoginDeadline(1500): a peer that connected and\n"
                      "  said nothing was dropped, and a connection opened after it\n"
                      "  was still served - so the drop was the deadline and not a\n"
                      "  hub that had stopped serving.\n" );
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
    WSACleanup ( );

    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
