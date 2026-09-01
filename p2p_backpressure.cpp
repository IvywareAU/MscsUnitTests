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
// p2p_backpressure.cpp - is the message budget a SLOPE or a CLIFF?
// ProductionPlan.md Stage 4 step 12.
//
// BACKGROUND. s_cP2PmsgMAX bounds the live P2Pmsg's in a process, and until
// this test the only thing that happened at it was a throw. Two consequences,
// and the second is worse than the first:
//
//   * BELOW the bound there was nothing at all. A peer could send as fast as
//     it liked and the library's answer was to keep accepting, right up to the
//     edge.
//   * AT the bound the failure was an exception raised on whichever thread
//     happened to post the message that crossed it. That is almost never the
//     thread, and almost never the connection, responsible for the pressure -
//     so an operator saw a QUEFULL out of a send path and learned nothing
//     about who caused it or what to do next.
//
// WHAT REPLACES IT. Two marks on the same budget. At or above the HIGH mark a
// connection stops asking its transport for another message; at or below the
// LOW mark it starts again. Stopping is expressed by NOT CALLING
// RecvP2PeerMsg() - the call that issues the next Recv() - so no read is
// outstanding, the socket buffer fills, and the TCP window closes. The peer is
// throttled by the transport, which is what backpressure means; nothing is
// discarded and nothing is refused.
//
// The gap between the two marks is hysteresis, and it is not decoration: with
// one mark a connection resumes the instant the budget dips a single message
// below it and is immediately re-held, which is a spin rather than a brake.
//
// WHAT IT MEASURES, in four phases against one logged-in peer. A LOGGED-IN
// peer and not a raw socket, unlike p2p_acceptcap: an application message from
// an unauthenticated peer is refused by GateAppMsgInbound() before it reaches
// the pump at all, so a raw flooder would measure the login gate. The peer
// being throttled here has done nothing wrong - it is sending legitimate
// traffic, and the pressure is the PROCESS's.
//
//   Phase 1 (THE CONTROL). Budget clear. The client sends K messages and the
//   sink must receive all K. Without this a hub that delivered nothing at all
//   would pass phase 2, which is the whole risk of a test whose positive
//   result is an absence.
//
//   Phase 2 (THE HOLD). The budget is pressed by parking a pump on a worker
//   thread that never pumps it and posting messages to it - the same technique
//   p2p_hubsnap uses, and for the same reason: the alternative is
//   manufacturing 37500 live messages. The client sends another K. The sink
//   must receive NONE of them, and its Throttled count must rise.
//
//   Phase 3 (IT IS A HOLD, NOT A DROP). The parked pump is closed, the budget
//   falls past the low mark, and all K of phase 2's messages must arrive.
//   THIS IS THE PHASE THAT MATTERS. Throttling that loses messages is dropping
//   with a better name, and phase 2 alone cannot tell the two apart.
//
//   Phase 4 (THE COUNTER). The decision must be visible to a reader that has
//   only the public API: the process-wide GetP2PmsgHeldCount(), and the
//   Throttled field of the hub's own snapshot (Stage 4 step 13 put the channel
//   there). A brake nobody can see being applied is indistinguishable from a
//   stall.
//
// WHAT THIS FOUND ON ITS FIRST ARMED RUN. P2PeerCon has always had a
// P2PsigCon_RECV signal whose comment says "Start P2PeerMsg receipt", and it
// could not have worked on a connection that had received anything: it goes
// through PostOVERLAPPED(), which refuses a buffer with dwBytesMax > 0 and a
// null pBuffer, and P2Peerio::RecvP2PeerMsg's stage 0 frees pBuffer on its
// FIRST call and never restores it. Nothing in the tree had ever signalled
// RECV, so nothing had ever noticed. Phase 3 threw "Corrupted OVERLAPPEDcon
// configuration" out of the resume the first time it ran. The resume is now
// P2PeerCon::RearmRecv(), and the signal routes through it, so the one path
// that claimed to restart receipt now does.
//
// THE MARKS ARE LOWERED FOR THE TEST, not for the product. SetP2PmsgBudgetMarks
// exists because a deployment may want to feel backpressure earlier than three
// quarters of the process budget - and because a gate that needed 37500 live
// messages would be too slow to run. The defaults are unchanged and always on.
//
// VERDICT = process EXIT CODE:
//   0  PASS   held under pressure, resumed on relief, nothing lost, counted
//   1  FAIL   the read was never held, never resumed, or lost the messages
//   2  SETUP  startup / listen / login failure (test inconclusive)
//   3  INCONCLUSIVE the parked pump could not be created, so the budget was
//                   never pressed and phases 2-4 prove nothing

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
static const P2PaddrSTR kSinkAddr = L"Bp.Sink";           // listens, and is held
static const P2PaddrSTR kSrcAddr  = L"Bp.Sink.Src";        // dials, and floods

static const int   kBatch      = 20;    // messages per phase
static const DWORD kMarkHigh   = 400;   // live-message marks for this run
static const DWORD kMarkLow    = 200;
static const int   kParkPosts  = 600;   // parked messages: comfortably over high

static volatile LONG g_nRecv    = 0;    // messages the sink's handler has seen
static HANDLE        g_hLoggedIn = NULL;

static void Log ( const char *msg )
{
    std::printf ( "[backpressure] %s\n", msg );
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

//  InterlockedCompareExchange is NOT in the Linux shim (Platform/p2ptypes.h
//  has Exchange, ExchangeAdd and Increment only), so an add of zero is the
//  portable read - refer p2p_expreg.cpp
static LONG AtomicRead ( volatile LONG *p )
{ return InterlockedExchangeAdd ( p, 0 ); }

// =========================================================================
class BpHub : public P2PeerHub
{
public:
    BpHub ( P2PaddrSTR strAddr, bool bSink )
      : P2PeerHub ( strAddr ), m_bSink ( bSink ) { }
    virtual ~BpHub ( ) { }

    void PostBatch ( const wchar_t *lpszBody, int nCount )
    {
        P2Psize_t nBytes =
            (P2Psize_t)( ( wcslen ( lpszBody ) + 1 ) * sizeof(wchar_t) );
        for ( int i = 0; i < nCount; ++i )
          PostP2PeerMsg ( new P2PeerMsg32 ( kSrcAddr, kSinkAddr
                                          , P2Pmsg_BCast, lpszBody, nBytes ) );
    }

protected:
    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        if ( m_bSink )
          InterlockedIncrement ( &g_nRecv );
        return msgHANDLED;
    }

    virtual conRESULT On_ConLogin ( P2PeerCon  *pCon
                                  , P2PaddrSTR  strThatP2Paddr
                                  , const void *pvLoginMsg
                                  , P2Psize_t   iSize ) override
    {
        conRESULT r = P2PeerHub::On_ConLogin ( pCon, strThatP2Paddr
                                             , pvLoginMsg, iSize );
        if ( m_bSink )
        {
            std::printf ( "[backpressure] sink: login FROM '%s'\n"
                        , N ( strThatP2Paddr ).c_str() );
            std::fflush ( stdout );
            if ( g_hLoggedIn ) SetEvent ( g_hLoggedIn );
        }
        return r;
    }

private:
    bool m_bSink;
};

// =========================================================================
//  The pressure. A second pump on a thread that never pumps it, so messages
//  posted to it stay live and the process budget stays spent - the same
//  technique p2p_hubsnap uses. A pump may only be cleaned up from its own
//  thread, hence the drain flag rather than a close from main
struct ParkCtx
{
    P2PmsgHubID    nHubID;
    P2PeerTarget  *pTarget;              // must not be null: PutP2Pmsg asserts
    volatile LONG  nPumpID;              // 0 = not up yet, ~0 = failed
    volatile LONG  bDrain;
};
static ParkCtx s_oPark = { 0, 0, 0, 0 };

static DWORD WINAPI ParkThread ( LPVOID )
{
    try
    {
      P2PumpID nPumpID = CreateP2PmsgPump ( s_oPark.nHubID, L"Parked"
                                          , s_oPark.pTarget );
      InterlockedExchange ( &s_oPark.nPumpID, (LONG)nPumpID );
    }
    catch ( P2Pevent *pEVT )
    {
      pEVT -> Cancel ( );
      InterlockedExchange ( &s_oPark.nPumpID, (LONG)~0 );
      return 1;
    }

    while ( !AtomicRead ( &s_oPark.bDrain ) )
      Sleep ( 50 );

    try   { CloseP2PmsgPump ( ); }
    catch ( P2Pevent *pEVT ) { pEVT -> Cancel ( ); }
    return 0;
}

// =========================================================================
//  Reads the sink hub's own snapshot. Public API only - refer p2p_hubsnap for
//  why ReadAnyInt() rather than c_int()
static long SnapField ( P2PeerHub& oHub, LPCWSTR lpszName )
{
    P3PmsgItem oSnap = oHub.Serialise ( 0 );
    if ( !oSnap.Exists ( lpszName ) )
      return -1;
    INT64 i64       = 0;
    bool  bUnsigned = false;
    if ( !oSnap.SelectItem ( lpszName ).r_data().ReadAnyInt ( i64, bUnsigned ) )
      return -1;
    return (long)i64;
}

//  Waits for the sink to have received nWant messages in total
static bool WaitForRecv ( LONG nWant, DWORD dwMs )
{
    for ( DWORD dwWaited = 0; ; dwWaited += 100 )
    {
        if ( AtomicRead ( &g_nRecv ) >= nWant ) return true;
        if ( dwWaited >= dwMs )                 return false;
        Sleep ( 100 );
    }
}

// =========================================================================
int main ( int argc, char *argv[] )
{
    const short nPort = (short)( argc > 1 ? std::atoi ( argv[1] ) : 7835 );

    std::printf ( "=== p2p_backpressure - a slope, not a cliff ===\n" );
    std::printf ( "Port : %d   marks: high=%lu low=%lu   batch=%d\n"
                , (int)nPort, (unsigned long)kMarkHigh
                , (unsigned long)kMarkLow, kBatch );
    std::printf ( "Asserting: a peer sending into a pressed budget is HELD and\n"
                  "           later RESUMED, losing nothing, and that the\n"
                  "           decision is visible in a counter.\n\n" );
    std::fflush ( stdout );

    g_hLoggedIn = CreateEvent ( NULL, FALSE, FALSE, NULL );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    //  Lowered for the run, not for the product. The defaults are three
    //  quarters and one half of s_cP2PmsgMAX and are always on
    try   { SetP2PmsgBudgetMarks ( kMarkHigh, kMarkLow ); }
    catch ( P2Pevent *pEVT )
    { pEVT->Cancel(); Log ( "SETUP: SetP2PmsgBudgetMarks() refused" ); return 2; }

    int nExit = 2;
    {
        BpHub oSink ( kSinkAddr, true  );
        BpHub oSrc  ( kSrcAddr,  false );
        //  RequireAuth(false): this is a RESOURCE bound. The peer here is
        //  legitimate and logged in - what is being measured is what happens
        //  when the process cannot keep up with it, which is not a
        //  who-may-speak question. Provisioning both hubs would add a
        //  dependency this test has no reason to carry
        oSink.RequireAuth ( false );
        oSrc .RequireAuth ( false );

        HANDLE hSinkThread = oSink.SpawnHub ( );
        HANDLE hSrcThread  = oSrc .SpawnHub ( );
        if ( !hSinkThread || !hSrcThread )
        { Log ( "SETUP: SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kSrcAddr, nPort );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }
        oSink.PostP2PeerCon ( pSvc );
        Sleep ( 500 );                   // let the listener bind before dialling

        P2PeerConWsa *pCli = P2PeerConWsa::ClientFactory ( kSinkAddr
                                                         , L"127.0.0.1", nPort );
        if ( !pCli ) { Log ( "SETUP: ClientFactory failed" ); return 2; }
        oSrc.PostP2PeerCon ( pCli );

        if ( WaitForSingleObject ( g_hLoggedIn, 15000 ) != WAIT_OBJECT_0 )
        {
            std::printf ( "\nRESULT: SETUP - the client never completed a login.\n"
                          "  Every phase below needs a logged-in peer: an\n"
                          "  application message from an unauthenticated one is\n"
                          "  refused by GateAppMsgInbound() before it reaches a\n"
                          "  pump, so nothing would be measured.\n" );
            oSink.CloseHub ( ); oSrc.CloseHub ( );
            WaitForSingleObject ( hSinkThread, 5000 ); CloseHandle ( hSinkThread );
            WaitForSingleObject ( hSrcThread,  5000 ); CloseHandle ( hSrcThread  );
            CleanupP2Pmsg ( ); WSACleanup ( );
            return 2;
        }
        Sleep ( 300 );                   // let the LoginAck land

        // -------------------------------------------------------------- 1 --
        Log ( "--- phase 1: control, budget clear ---" );
        const long nHeld0 = SnapField ( oSink, L"Throttled" );
        oSrc.PostBatch ( L"control", kBatch );
        const bool bControl = WaitForRecv ( kBatch, 15000 );
        std::printf ( "[backpressure] control: sink received %ld of %d"
                      "   live=%lu Throttled=%ld\n"
                    , (long)AtomicRead ( &g_nRecv ), kBatch
                    , (unsigned long)GetP2PmsgCount ( (P2PumpID)~0 ), nHeld0 );
        std::fflush ( stdout );

        // -------------------------------------------------------------- 2 --
        Log ( "--- phase 2: press the budget, then send again ---" );
        s_oPark.nHubID  = oSink.GetHubID ( );
        s_oPark.pTarget = &oSink;
        HANDLE hPark = CreateThread ( 0, 0, ParkThread, 0, 0, 0 );

        LONG nParkPump = 0;
        for ( int i = 0; i < 100 && nParkPump == 0; ++i )
        { Sleep ( 50 ); nParkPump = AtomicRead ( &s_oPark.nPumpID ); }
        bool bParked = ( nParkPump != 0 && nParkPump != (LONG)~0 );

        bool  bPressed = false, bHeldQuiet = false, bCounted = false;
        long  nHeldHub = -1;
        DWORD dwHeldProc0 = GetP2PmsgHeldCount ( );
        DWORD dwHeldProc  = dwHeldProc0;
        LONG  nRecvAtPress = AtomicRead ( &g_nRecv );

        if ( bParked )
        {
          const wchar_t szPad[] = L"parked";
          for ( int i = 0; i < kParkPosts; ++i )
            PostP2Pmsg ( new P2PeerMsg32 ( L"Bp.Park", L"Bp.Park"
                                         , P2Pmsg_BCast, szPad
                                         , (P2Psize_t)sizeof(szPad) )
                       , (P2PumpID)nParkPump );
          Sleep ( 300 );
          bPressed = P2PmsgBudgetPressed ( );
          std::printf ( "[backpressure] pressed: live=%lu high=%lu -> %s\n"
                      , (unsigned long)GetP2PmsgCount ( (P2PumpID)~0 )
                      , (unsigned long)GetP2PmsgBudgetHigh ( )
                      , bPressed ? "PRESSED" : "not pressed" );
          std::fflush ( stdout );

          oSrc.PostBatch ( L"held", kBatch );

          //  Long enough that "the sink was merely slow" is not an
          //  explanation: phase 1's whole batch landed inside this window
          Sleep ( 4000 );
          bHeldQuiet  = AtomicRead ( &g_nRecv ) == nRecvAtPress;
          nHeldHub    = SnapField ( oSink, L"Throttled" );
          dwHeldProc  = GetP2PmsgHeldCount ( );
          bCounted    = nHeldHub > nHeld0 && dwHeldProc > dwHeldProc0;
          std::printf ( "[backpressure] held: sink received %ld (was %ld)"
                        "   Throttled=%ld (was %ld)   process holds=%lu (was %lu)\n"
                      , (long)AtomicRead ( &g_nRecv ), (long)nRecvAtPress
                      , nHeldHub, nHeld0
                      , (unsigned long)dwHeldProc, (unsigned long)dwHeldProc0 );
          std::fflush ( stdout );
        }

        // -------------------------------------------------------------- 3 --
        bool bResumed = false;
        if ( bParked )
        {
          Log ( "--- phase 3: release, and nothing may be lost ---" );
          InterlockedExchange ( &s_oPark.bDrain, 1 );
          WaitForSingleObject ( hPark, 10000 );
          Sleep ( 300 );
          std::printf ( "[backpressure] released: live=%lu low=%lu -> %s\n"
                      , (unsigned long)GetP2PmsgCount ( (P2PumpID)~0 )
                      , (unsigned long)GetP2PmsgBudgetLow ( )
                      , P2PmsgBudgetRelieved ( ) ? "RELIEVED" : "still pressed" );
          std::fflush ( stdout );

          bResumed = WaitForRecv ( kBatch * 2, 15000 );
          std::printf ( "[backpressure] resumed: sink received %ld of %d\n"
                      , (long)AtomicRead ( &g_nRecv ), kBatch * 2 );
          std::fflush ( stdout );
        }
        else
        {
          InterlockedExchange ( &s_oPark.bDrain, 1 );
          WaitForSingleObject ( hPark, 10000 );
        }
        if ( hPark ) CloseHandle ( hPark );

        // ---------------------------------------------------------- verdict -
        if ( !bControl )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the CONTROL batch never arrived (%ld of %d).\n"
              "  Phase 2's positive result is an ABSENCE - messages that do not\n"
              "  arrive - so a link that delivers nothing at all would pass it.\n"
              "  This control is what makes that reading impossible, and it did\n"
              "  not hold. Nothing below is measured. Check wsa_mesh and\n"
              "  p2p_bigreport first: neither depends on backpressure.\n"
            , (long)AtomicRead ( &g_nRecv ), kBatch );
            nExit = 3;
        }
        else if ( !bParked )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - the parked pump could not be created.\n"
              "  It is the only thing in this test that presses the budget, and\n"
              "  without pressure a connection that never holds anything looks\n"
              "  exactly like one that holds correctly. CreateP2PmsgPump()\n"
              "  refuses past the hub's PumpsMax and refuses a thread that\n"
              "  already owns a pump.\n" );
            nExit = 3;
        }
        else if ( !bPressed )
        {
            std::printf (
              "\nRESULT: INCONCLUSIVE - %d parked messages did not reach the\n"
              "  high mark of %lu (live=%lu).\n"
              "  The budget counts LIVE P2Pmsg's process-wide, so either the\n"
              "  posts were released faster than they were made - which would\n"
              "  mean something is pumping the parked pump - or the mark was\n"
              "  not applied. Check SetP2PmsgBudgetMarks() returned without\n"
              "  throwing.\n"
            , kParkPosts, (unsigned long)GetP2PmsgBudgetHigh ( )
            , (unsigned long)GetP2PmsgCount ( (P2PumpID)~0 ) );
            nExit = 3;
        }
        else if ( !bHeldQuiet )
        {
            std::printf (
              "\nRESULT: FAIL - THE READ WAS NEVER HELD (%ld received, expected"
              " to stay at %ld).\n"
              "  The budget was at its high mark and a logged-in peer kept\n"
              "  sending, and the connection kept parsing. That is the CLIFF the\n"
              "  step exists to remove: nothing happens below the ceiling, and\n"
              "  at the ceiling a thread that did nothing wrong takes a QUEFULL.\n"
              "  The hold is HoldRecvForBackpressure() in the recv loop's\n"
              "  CONDITION - not at the bottom of its body, which would take one\n"
              "  more message off the peer before deciding.\n"
            , (long)AtomicRead ( &g_nRecv ), (long)nRecvAtPress );
            nExit = 1;
        }
        else if ( !bCounted )
        {
            std::printf (
              "\nRESULT: FAIL - THE DECISION IS NOT VISIBLE (hub Throttled=%ld,"
              " was %ld; process holds=%lu, was %lu).\n"
              "  The read WAS held - phase 2's messages did not arrive - and no\n"
              "  counter moved. A brake nobody can see being applied is\n"
              "  indistinguishable from a stall, and an operator watching a hub\n"
              "  go quiet has no way to tell 'holding the line' from 'wedged'.\n"
              "  The step's exit criterion is explicit that the decision must be\n"
              "  visible in a counter. Check BumpP2PmsgHeldCount() in\n"
              "  HoldRecvForBackpressure(), and GetP2PmsgHubHeldCount() feeding\n"
              "  the Throttled field of P2PeerHub::Serialise().\n"
            , nHeldHub, nHeld0
            , (unsigned long)dwHeldProc, (unsigned long)dwHeldProc0 );
            nExit = 1;
        }
        else if ( !bResumed )
        {
            std::printf (
              "\nRESULT: FAIL - THE HELD MESSAGES WERE LOST (%ld of %d).\n"
              "  The budget recovered past its low mark and the connection never\n"
              "  started reading again, so phase 2's batch is still sitting in a\n"
              "  socket buffer nobody will ever drain. THIS IS THE PHASE THAT\n"
              "  MATTERS: a hold that does not resume is a drop with a better\n"
              "  name, and phase 2 on its own cannot tell the two apart.\n"
              "  The resume is On_PITimer()'s backpressure branch calling\n"
              "  RearmRecv(). Check the poll timer is armed by\n"
              "  HoldRecvForBackpressure(), that it is NOT cancelled by\n"
              "  OnLogin(), and that P2PmsgBudgetRelieved() uses the LOW mark:\n"
              "  a resume keyed on the high mark spins instead of releasing.\n"
              "  RearmRecv() and NOT PostOVERLAPPED(): the latter refuses a\n"
              "  recv buffer whose pBuffer the io layer freed on its first\n"
              "  call, which is every connection that has received anything.\n"
            , (long)AtomicRead ( &g_nRecv ), kBatch * 2 );
            nExit = 1;
        }
        else
        {
            std::printf (
              "\nRESULT: PASS - the budget is a slope.\n"
              "  A logged-in peer sent %d messages into a clear budget and all\n"
              "  %d arrived. The budget was then pressed to its high mark of\n"
              "  %lu and the same peer sent %d more: NONE arrived for four\n"
              "  seconds - a window that comfortably contained the whole of the\n"
              "  control batch - while the hub's Throttled count rose from %ld\n"
              "  to %ld and the process hold count from %lu to %lu. The pressure\n"
              "  was then released and all %d of the held messages arrived. So\n"
              "  the peer was HELD and not refused, RESUMED and not dropped, and\n"
              "  the decision was legible from outside the process the whole\n"
              "  time.\n"
            , kBatch, kBatch, (unsigned long)kMarkHigh, kBatch
            , nHeld0, nHeldHub
            , (unsigned long)dwHeldProc0, (unsigned long)dwHeldProc, kBatch );
            nExit = 0;
        }

        Log ( "shutdown begin" );
        oSrc .CloseHub ( );
        oSink.CloseHub ( );
        WaitForSingleObject ( hSrcThread,  8000 ); CloseHandle ( hSrcThread  );
        WaitForSingleObject ( hSinkThread, 8000 ); CloseHandle ( hSinkThread );
    }
    CleanupP2Pmsg ( );
    WSACleanup ( );

    std::fflush ( stdout );
    return nExit;
}
