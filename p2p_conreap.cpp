//
//  p2p_conreap - does a peer that connects, SAYS NOTHING and DISCONNECTS get
//                reaped?
//  ProductionPlan.md F-S4-1.
//
//  WHAT THE DEFECT WAS. On Windows it did not. A stream socket announces an
//  orderly close by completing an outstanding read with ZERO BYTES, and that
//  is byte-for-byte what an ARMING post looks like at the same branch:
//  PostOVERLAPPED() and RearmRecv() do not issue a read, they
//  PostQueuedCompletionStatus(.., 0, ..) so the completion re-enters
//  On_QueuedCompletionStatus and RecvP2PeerMsg() issues the real one. Both
//  arrive as a success carrying zero. The branch took the FIN for an arming
//  post, parsed no message, posted no further read and returned - so the
//  connection was never dropped and never destroyed, and the destructor that
//  decrements the accepted tally never ran.
//
//  WHAT IT COST, and it is why this carries the security label. On Windows
//  both accept bounds counted connections EVER ACCEPTED rather than
//  connections currently held. SetMaxAccepted(1024) retired a service
//  permanently after 1024 connect-and-leave cycles from anywhere, and the
//  per-source share retired one address after its share - which makes the
//  admission-control protection a slower version of the attack it exists to
//  refuse. It also leaked a connection object per cycle.
//
//  WHY LINUX WAS CLEAN. The io_uring shim marks the op at submission
//  (OVERLAPPED::_p2p_op = P2POP_READ) and reports res==0 on a read as
//  ERROR_HANDLE_EOF, which the recv branch's existing failure path already
//  drops. The fix gives Windows the same mark - OVERLAPPEDcon::bRecvSubmitted,
//  set in P2Peerio::Recv, read and cleared in
//  P2PeerCon::On_QueuedCompletionStatus - and synthesises the SAME error code,
//  so both platforms leave by one route.
//
//  WHAT THIS MEASURES, and the four phases are not decoration. Each one exists
//  because the other three would pass without it.
//
//    Phase 1 (AT REST). Accepted is 0 with nothing connected. Without it a
//    counter that was never anything but 0 would sail through phase 3.
//
//    Phase 2 (THE POSITIVE CONTROL). Three raw sockets connect and Accepted
//    reads exactly 3. This is the phase that makes phase 3 mean anything: a
//    hub that refused all three, or that never counted them, would also
//    report 0 after they closed, and would pass a test that only looked at
//    the fall. RAW sockets - not logged-in peers - because what is being
//    counted is OCCUPANCY, and a peer does not have to be allowed to speak in
//    order to occupy. It is also the exact shape of the abuse the bound
//    exists to refuse.
//
//    Phase 3 (THE DECISION). All three close. Accepted must fall to 0. This
//    is the finding, stated as a proposition that can go red.
//
//    Phase 4 (THE NEGATIVE CONTROL, and it is the one that matters most). A
//    fourth raw peer connects and STAYS. Accepted must read 1 and must STILL
//    read 1 a second and a half later. Without this phase the cheapest way to
//    pass phases 1-3 is to drop every connection the moment it is accepted -
//    which is not a hypothetical failure mode: it is the obvious fix, it was
//    tried, and it is what it did. Treating a zero-byte success as a close
//    without the submission mark kills the connection on its own arming post.
//
//  NO LOGIN DEADLINE ANYWHERE IN THIS TEST, and that is a requirement rather
//  than a default. SetLoginDeadline() is a reaping path that works on both
//  platforms, so a deadline armed here would reap these peers for a reason
//  that has nothing to do with the close and the test would pass against the
//  defect. DEF_P2PeerConLogin is 0 and this sets it to 0 explicitly; the
//  banner prints it back so a reader does not have to take that on trust.
//
//  RequireAuth(false) for the same class of reason: requiring authentication
//  would drop a silent raw peer on its own account.
//
//  VERDICT = process EXIT CODE:
//    0  PASS   held, then reaped, and a live peer was not reaped
//    1  FAIL   the count did not fall (F-S4-1), or fell for a peer still there
//    2  SETUP  startup / listen / dial failure (test inconclusive)
//

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConWsa.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

// ---------------------------------------------------------------------------
static const P2PaddrSTR kServerAddr = L"Reap.Server";
static const P2PaddrSTR kDomain     = L"Reap.*";

static void Log ( const char *msg )
{
    std::printf ( "[conreap] %s\n", msg );
    std::fflush ( stdout );
}

// ---------------------------------------------------------------------------
//  A raw TCP peer: connects and says nothing the library would recognise.
//  The hub holds it regardless, which is the point
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

//  An ORDERLY close - closesocket() on a socket with nothing outstanding sends
//  FIN, which is the completion this whole test is about. Not an abort
static void RawClose ( SOCKET &s )
{
    if ( s != INVALID_SOCKET ) { closesocket ( s ); s = INVALID_SOCKET; }
}

// ---------------------------------------------------------------------------
//  Waits for the accepted tally to reach a target and returns what it ended on,
//  rather than only whether it got there - a number in the log is worth more
//  than a boolean when this goes red. A bounded poll rather than one Sleep:
//  the drop is delivered on the hub's pump thread, and how long that takes is
//  a property of the machine, not of the fix
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

// =========================================================================
class ReapHub : public P2PeerHub
{
public:
    ReapHub ( P2PaddrSTR strAddr ) : P2PeerHub ( strAddr ) { }
    virtual ~ReapHub ( ) { }
};

// =========================================================================
int main ( int argc, char **argv )
{
    const short nPort = (short)( argc > 1 ? std::atoi ( argv[1] ) : 7842 );

    std::printf ( "=== p2p_conreap - the peer that connects, says nothing and leaves ===\n" );
    std::printf ( "Port : %d\n", (int)nPort );
    std::printf ( "Asserting: an accepted connection whose peer sends FIN without\n"
                  "           ever speaking is REAPED, and one whose peer is still\n"
                  "           there is NOT.  ProductionPlan.md F-S4-1.\n\n" );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    WSADATA oWsaData;
    WSAStartup ( MAKEWORD(2,2), &oWsaData );

    int nExit = 2;
    {
        ReapHub oServer ( kServerAddr );
        oServer.RequireAuth ( false );
        HANDLE hServerThread = oServer.SpawnHub ( );
        if ( !hServerThread ) { Log ( "SETUP: SpawnHub() failed" ); return 2; }

        P2PeerConWsa *pSvc = P2PeerConWsa::ServiceFactory ( kDomain, nPort );
        if ( !pSvc )
        {
          //  The hub is already RUNNING at this point, so this path cannot just
          //  return - it has a thread to shut down and a handle to release, the
          //  same two things the success path at the bottom does.  Before
          //  F-S4-2 it did neither, and the setup failure it exists to report
          //  would have been a leak on top of a leak
          Log ( "SETUP: ServiceFactory failed" );
          oServer.CloseHub ( );
          WaitForSingleObject ( hServerThread, 3000 );
          CloseHandle ( hServerThread );
          return 2;
        }

        //  UNBOUND and UNDEADLINED, set rather than assumed. A cap would refuse
        //  in phase 2 and a deadline would reap in phase 3 for a reason that is
        //  not the close
        pSvc -> SetMaxAccepted          ( 0 );
        pSvc -> SetMaxAcceptedPerSource ( 0 );
        pSvc -> SetLoginDeadline        ( 0 );
        oServer.PostP2PeerCon ( pSvc );
        Sleep ( 500 );

        std::printf ( "[conreap] service: MaxAccepted=%ld MaxPerSource=%ld LoginDeadline=%ld\n"
                    , pSvc->GetMaxAccepted ( )
                    , pSvc->GetMaxAcceptedPerSource ( )
                    , (long)pSvc->GetLoginDeadline ( ) );
        std::fflush ( stdout );

        // -------------------------------------------------------------- 1 --
        Log ( "--- phase 1: at rest ---" );
        const long xRest     = pSvc -> GetAcceptedCount ( );
        const bool bRestZero = xRest == 0;
        std::printf ( "[conreap] at rest        Accepted=%ld (want 0)\n", xRest );

        // -------------------------------------------------------------- 2 --
        Log ( "--- phase 2: three raw peers connect and are HELD ---" );
        SOCKET a1 = RawConnect ( nPort ); Sleep ( 250 );
        SOCKET a2 = RawConnect ( nPort ); Sleep ( 250 );
        SOCKET a3 = RawConnect ( nPort ); Sleep ( 250 );
        const bool bDialled = a1 != INVALID_SOCKET &&
                              a2 != INVALID_SOCKET &&
                              a3 != INVALID_SOCKET;

        //  Exactly 3 - not "at least 3". A service that also counted itself,
        //  or that counted each child's share of its service's counter, would
        //  clear a >= test and be wrong
        const long xHeld = bDialled ? PollAccepted ( pSvc, 3, 3000 ) : -1;
        const bool bHeld = xHeld == 3;
        std::printf ( "[conreap] three held     Accepted=%ld (want 3)\n", xHeld );

        // -------------------------------------------------------------- 3 --
        Log ( "--- phase 3: all three close.  THE DECISION ---" );
        RawClose ( a1 ); RawClose ( a2 ); RawClose ( a3 );

        //  6 seconds is generous against a drop delivered on the next
        //  completion, and it is generous ON PURPOSE: the defect this closes
        //  did not report 3 for six seconds, it reported 3 for ever
        const long xReaped = PollAccepted ( pSvc, 0, 6000 );
        const bool bReaped = xReaped == 0;
        std::printf ( "[conreap] all closed     Accepted=%ld (want 0)\n", xReaped );

        // -------------------------------------------------------------- 4 --
        Log ( "--- phase 4: a peer that is STILL THERE must not be reaped ---" );
        SOCKET b1 = RawConnect ( nPort );
        const bool bDialled4 = b1 != INVALID_SOCKET;
        const long xLive     = bDialled4 ? PollAccepted ( pSvc, 1, 3000 ) : -1;

        //  And it must STILL be held after the connection has had every
        //  opportunity to be dropped by its own arming post
        Sleep ( 1500 );
        const long xLiveStill = bDialled4 ? pSvc->GetAcceptedCount ( ) : -1;
        const bool bLiveHeld  = xLive == 1 && xLiveStill == 1;
        std::printf ( "[conreap] one live       Accepted=%ld then %ld (want 1 then 1)\n"
                    , xLive, xLiveStill );
        RawClose ( b1 );

        // ------------------------------------------------------------------
        std::printf ( "\n[conreap] rest=%s held=%s reaped=%s liveheld=%s\n"
                    , bRestZero ? "0"    : "NOT 0"
                    , bHeld     ? "3"    : "NOT 3"
                    , bReaped   ? "0"    : "NOT 0"
                    , bLiveHeld ? "held" : "DROPPED" );

        if ( !bDialled || !bDialled4 )
        {
          std::printf ( "\nRESULT: SETUP - a raw peer could not connect, so nothing\n"
                        "  below was measured.\n" );
          nExit = 2;
        }
        //  DIALLED BUT NOT HELD is not a setup problem and must not be
        //  reported as one.  All three sockets CONNECTED - the service
        //  accepted them - and the count is 0, which means the hub took them
        //  and let go again with all three peers still on the other end.
        //  That is the obvious fix's failure mode arriving one phase before
        //  phase 4 would catch it, and calling it SETUP would send a reader
        //  looking for a port conflict instead of at the recv branch
        else if ( bDialled && xHeld == 0 )
        {
          std::printf ( "\nRESULT: FAIL - THE SERVICE DROPPED ALL THREE AT ACCEPT "
                        "(held %ld, want 3).\n"
                        "  Three sockets CONNECTED and the service is holding\n"
                        "  none of them, with every peer still there.  Not a\n"
                        "  setup failure: the connections were made and then\n"
                        "  thrown away.  This is what treating ANY zero-byte\n"
                        "  success on the recv OVERLAPPED as an orderly close\n"
                        "  does - the ARMING post that starts every connection\n"
                        "  is exactly that, so each one closes itself on its own\n"
                        "  first completion.  Check that\n"
                        "  P2PeerCon::On_QueuedCompletionStatus still requires\n"
                        "  OVERLAPPEDcon::bRecvSubmitted before reading a zero\n"
                        "  as FIN.  Refer ProductionPlan.md F-S4-1.\n"
                      , xHeld );
          nExit = 1;
        }
        else if ( !bRestZero || !bHeld )
        {
          std::printf ( "\nRESULT: SETUP - the service did not HOLD three raw peers\n"
                        "  (at rest %ld, held %ld).  Phase 3 cannot mean anything\n"
                        "  until it does: a count that never rose would fall to 0\n"
                        "  on its own.\n", xRest, xHeld );
          nExit = 2;
        }
        else if ( !bReaped )
        {
          std::printf ( "\nRESULT: FAIL - THE CONNECTIONS WERE NEVER REAPED "
                        "(read %ld, want 0).\n"
                        "  Three peers connected, said nothing and closed, and the\n"
                        "  service still counts them.  This is ProductionPlan.md\n"
                        "  F-S4-1: the peer's FIN arrives as a zero-byte SUCCESS\n"
                        "  completion, indistinguishable from an arming post unless\n"
                        "  the submission is marked.  Check\n"
                        "  OVERLAPPEDcon::bRecvSubmitted - set in P2Peerio::Recv,\n"
                        "  read and cleared in P2PeerCon::On_QueuedCompletionStatus's\n"
                        "  recv branch - and P2PeerConWsa::RecvZeroIsOrderlyClose().\n"
                        "  With the count of connections EVER ACCEPTED standing in\n"
                        "  for the count currently HELD, both accept bounds retire a\n"
                        "  service permanently after enough connect-and-leave cycles.\n"
                      , xReaped );
          nExit = 1;
        }
        else if ( !bLiveHeld )
        {
          std::printf ( "\nRESULT: FAIL - A LIVE PEER WAS REAPED "
                        "(read %ld then %ld, want 1 then 1).\n"
                        "  The close detection is firing on something that is not a\n"
                        "  close.  This is the OBVIOUS fix's failure mode and it was\n"
                        "  measured before the real one was written: treating any\n"
                        "  zero-byte success on the recv OVERLAPPED as an orderly\n"
                        "  close drops every connection at accept, because the\n"
                        "  ARMING post that starts a connection is exactly that.\n"
                        "  The submission mark is what tells them apart.\n"
                      , xLive, xLiveStill );
          nExit = 1;
        }
        else
        {
          std::printf ( "\nRESULT: PASS - three raw peers were HELD at 3, and the\n"
                        "  count returned to 0 after they closed with no login\n"
                        "  deadline armed and no cap in play, so the reaping is the\n"
                        "  close and not a timer.  A fourth peer that stayed was\n"
                        "  still held 1.5s later, so the close detection is not\n"
                        "  firing on the arming post.\n" );
          nExit = 0;
        }

        //  CLOSE THE HANDLE SpawnHub() HANDED BACK - F-S4-2.
        //  NOTES: This test spawned a hub and never released the thread handle,
        //         so it leaked 80 bytes in 3 allocations on every run: the
        //         HKind handle itself, the P2PThreadCtl control block and its
        //         shared-count (Platform/p2pthread.h:147-156).  Every other
        //         multi-hub harness in this suite already did this; this one
        //         was written without it and nothing noticed.
        //       : WHY NOTHING NOTICED is the part worth keeping.  A leaked
        //         handle in a process that is about to exit costs nothing a
        //         test can observe, so no assertion here could ever have
        //         failed on it - only a sanitiser can see it, and until
        //         2026-08-20 p2p_conreap had never been run under one.  The
        //         Linux gate runs `-L security` and this test IS in that
        //         label, but the tree that last reported that figure predated
        //         it.  A label total quoted from a tree missing two of its
        //         members is a figure about a different label.
        //       : The wait is not redundant even though CloseHub() now JOINS
        //         the pump thread (C-4).  It costs nothing when the join has
        //         already happened, and it is what the rest of the suite does
        //         - a shutdown that depends on CloseHub()'s internals staying
        //         as they are today is a shutdown that breaks quietly the day
        //         they change.
        oServer.CloseHub ( );
        WaitForSingleObject ( hServerThread, 3000 );
        CloseHandle ( hServerThread );
    }

    WSACleanup ( );
    CleanupP2Pmsg ( );
    return nExit;
}
