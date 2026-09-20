// p2p_dmxdead: does a DMX send to a peer that has GONE report that it failed,
// or does it report that it worked?
//
// This is the second, smaller exit criterion of OpenCodeWork.md item 7, and
// it is a different defect from that row's main one. Item 7 is about a
// connection that is never told its peer left. This is about what happens to
// a connection that HAS been told - m_pConThat is already cleared - and is
// then asked to send.
//
// WHAT IS WRONG. P2PeerioDmx::SendP2PeerMsg refuses when the peer is gone:
//
//     if ( m_pCon->GetUDState() == 0 )          // GetUDState() IS m_pConThat
//     {                                         // (P2PeerConDmx.cpp:961-963)
//       pOVERLAPPEDsend -> hr = ERROR_OPERATION_ABORTED;
//       m_pCon -> PostOVERLAPPED ( pOVERLAPPEDsend );
//       return 0;
//     }
//
// and the abort never survives. PostOVERLAPPED calls prepareOVERLAPPED, which
// assigns hr = S_OK (P2PeerCon.cpp:1203), so the completion arrives as a
// SUCCESS. The send branch treats a success as DELIVERED and deletes the
// message as sent (P2PeerCon.cpp:691-697). So a message handed to a peer that
// no longer exists is destroyed, and the sender is told it went.
//
// Measured 2026-09-21 by printing hr at the completion and reading
// 0x00000000 where ERROR_OPERATION_ABORTED had been written one line above.
//
// WHAT THIS GATE ASSERTS. The server hub is closed, joined AND destroyed, so
// the client's connection is detached - GetUDState() == 0, checked as a
// PRECONDITION rather than assumed, because a send that does not reach the
// refusal measures nothing at all. The client then posts a message straight
// onto that connection and must learn that it failed: On_ConClose on the
// client hub. Today it never comes.
//
// WHY THE MESSAGE IS POSTED ON THE CONNECTION, not on the hub. P2PeerCon::
// PostP2PeerMsg (P2PeerCon.cpp:1833) queues on that one connection and kicks
// its send OVERLAPPED (:1871-1876), so SendP2PeerMsg is reached whatever the
// hub would have made of an address whose peer has gone. Routing through the
// hub would have made a red result ambiguous: "the send failed silently" and
// "the hub never found a route" look identical from outside.
//
// THE CONTROL (--alive) IS LOAD-BEARING, and not for symmetry. The fix makes
// a dead-peer send drop the connection; the control has to show that a send
// does not drop a connection merely by being a send. With the peer UP, the
// same message on the same call must ARRIVE - asserted positively, by the
// server's On_P2PeerBCast - and no close may occur.
//
// WHAT THIS GATE DOES NOT ESTABLISH. The RECV half of the same defect, at
// P2PeerioDmx.cpp:177-181, is NOT fixed and NOT gated here. It was measured
// on 2026-09-21 and it destabilises teardown: with it fixed, p2pweb_w6 - a
// test with no DMX in its name, whose hub chain is wired with P2PeerConDmx -
// SEGFAULTs after its last assertion. A recv is re-armed constantly during
// shutdown, so turning a silent re-arm into a connection drop changes the
// order every in-process chain comes down in. That half belongs with item 7's
// teardown work. This half does not, and is gated here because it is
// reachable, observable and measured stable over repeated runs.
//
// Verdict = process EXIT CODE: 0 PASS | 1 FAIL | 2 SETUP | 3 INCONCLUSIVE.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConDmx.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <atomic>
#include <cstdio>
#include <cstring>

static LPCTSTR          kServiceName = _T("P2PdmxDeadProbe");
static const P2PaddrSTR kServerAddr  = L"DmxDead.Server";
static const P2PaddrSTR kClientAddr  = L"DmxDead.Client";

static void Log ( const char *lpszMsg )
{
    std::printf ( "[dmxdead] %s\n", lpszMsg );
    std::fflush ( stdout );
}

class DeadHub : public P2PeerHub
{
public:
    DeadHub ( P2PaddrSTR strAddr, const char *lpszRole )
      : P2PeerHub ( strAddr ), m_lpszRole ( lpszRole )
      , m_bServed ( false ), m_bClosed ( false ), m_bGotMsg ( false ) {}
    virtual ~DeadHub ( ) { CloseHub ( ); }

    bool Served ( ) const { return m_bServed; }
    bool Closed ( ) const { return m_bClosed; }
    bool GotMsg ( ) const { return m_bGotMsg; }

protected:
    virtual conRESULT
      On_ConLoginAck ( P2PeerCon  *pCon
                     , P2PaddrSTR  strThisP2Paddr
                     , P2PaddrSTR  strThatP2Paddr
                     , const void *pvLoginAck
                     , P2Psize_t   iSize ) override
    {
        m_bServed = true;
        std::printf ( "[%s] login ack\n", m_lpszRole );
        std::fflush ( stdout );
        return P2PeerHub::On_ConLoginAck ( pCon, strThisP2Paddr, strThatP2Paddr
                                         , pvLoginAck, iSize );
    }

    virtual conRESULT On_ConClose ( P2PeerCon *pCon ) override
    {
        m_bClosed = true;
        std::printf ( "[%s] con closed\n", m_lpszRole );
        std::fflush ( stdout );
        return P2PeerHub::On_ConClose ( pCon );
    }

    virtual msgRESULT On_P2PeerBCast ( P2PeerMsg *pMsg ) override
    {
        m_bGotMsg = true;
        std::printf ( "[%s] message received\n", m_lpszRole );
        std::fflush ( stdout );
        return msgHANDLED;
    }

private:
    const char       *m_lpszRole;
    //  std::atomic, NOT volatile.  These are written on the hub's pump
    //  thread and read by the polling loop on the main thread, and volatile
    //  orders nothing and publishes nothing - it only stops the compiler
    //  caching the load.  Windows happened to behave; the Linux TSan gate
    //  reported the race on the first run it ever saw these harnesses
    //  (2026-09-21), which is the second time a test in this suite has been
    //  the thing a sanitiser caught.
    std::atomic<bool> m_bServed;
    std::atomic<bool> m_bClosed;
    std::atomic<bool> m_bGotMsg;
};

//  Polls rather than sleeping a fixed span, so a slow machine costs time
//  instead of a false verdict
template <typename PRED>
static bool WaitFor ( PRED fnDone, DWORD dwWaitMs )
{
    for ( DWORD dwWaited = 0; ; dwWaited += 50 )
    {
      if ( fnDone ( ) ) return true;
      if ( dwWaited >= dwWaitMs ) return false;
      Sleep ( 50 );
    }
}

static void PostOne ( P2PeerCon *pCon )
{
    static const wchar_t kBody[] = L"dmxdead";
    pCon -> PostP2PeerMsg (
        new P2PeerMsg32 ( kClientAddr, kServerAddr, P2Pmsg_BCast
                        , (void *)kBody, (P2Psize_t)sizeof(kBody) ) );
}

int main ( int argc, char *argv[] )
{
    bool bAlive = false;
    for ( int i = 1; i < argc; ++i )
      if ( std::strcmp ( argv[i], "--alive" ) == 0 )
        bAlive = true;

    std::printf ( "=== p2p_dmxdead - a DMX send to a departed peer%s ===\n",
                  bAlive ? " (CONTROL: peer alive)" : "" );
    std::printf ( "Asserting: %s\n\n",
                  bAlive
                  ? "with the peer UP, the message ARRIVES and the link\n"
                    "           stays up."
                  : "with the peer GONE, the sender is TOLD - the send fails\n"
                    "           and the connection closes." );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }

    int nExit = 2;
    {
        DeadHub *pServer = new DeadHub ( kServerAddr, "SERVER" );
        pServer -> RequireAuth ( false );
        HANDLE hServer = pServer -> SpawnHub ( );
        if ( !hServer ) { Log ( "SETUP: server SpawnHub() failed" ); return 2; }
        pServer -> PostP2PeerCon (
            P2PeerConDmx::ServiceFactory ( kClientAddr, kServiceName ) );
        Sleep ( 750 );

        DeadHub oClient ( kClientAddr, "CLIENT" );
        oClient.RequireAuth ( false );
        HANDLE hClient = oClient.SpawnHub ( );
        if ( !hClient ) { Log ( "SETUP: client SpawnHub() failed" ); return 2; }

        P2PeerConDmx *pCli =
            P2PeerConDmx::ClientFactory ( kServerAddr, kServiceName );
        if ( !pCli ) { Log ( "SETUP: ClientFactory failed" ); return 2; }
        oClient.PostP2PeerCon ( pCli );

        if ( !WaitFor ( [&]{ return oClient.Served ( ); }, 8000 ) )
        {
            std::printf (
              "\nRESULT: SETUP - the link never came up, so there is no\n"
              "  send path here to measure.  p2p_dmxcap covers the accept\n"
              "  path; run it first.\n" );
            nExit = 2;
        }
        else if ( bAlive )
        {
            // ---- Control: the peer is up ------------------------------
            Log ( "--- control: peer UP, the message must arrive ---" );
            PostOne ( pCli );
            const bool bGot   = WaitFor ( [&]{ return pServer->GotMsg ( ); }, 8000 );
            const bool bShut  = oClient.Closed ( );
            std::printf ( "[dmxdead] arrived=%s clientClosed=%s\n",
                          bGot  ? "yes" : "NO",
                          bShut ? "YES" : "no" );
            std::fflush ( stdout );

            if ( bGot && !bShut )
            {
                std::printf (
                  "\nRESULT: PASS - the control holds.\n"
                  "  With the peer up the same call delivers and the link\n"
                  "  stays open, so a close in the main run is attributable\n"
                  "  to the peer being GONE and not to sending as such.\n" );
                nExit = 0;
            }
            else
            {
                std::printf (
                  "\nRESULT: FAIL - THE CONTROL DID NOT HOLD.\n"
                  "  A send over a healthy DMX link must arrive and must not\n"
                  "  close the connection.  Until that is true the main run's\n"
                  "  verdict means nothing.\n" );
                nExit = 1;
            }
        }
        else
        {
            // ---- Phase 1: the peer leaves, completely -----------------
            Log ( "--- phase 1: the server closes, joins and is destroyed ---" );
            pServer -> CloseHub ( );
            WaitForSingleObject ( hServer, 5000 );
            CloseHandle ( hServer );
            delete pServer;
            pServer = 0;
            hServer = 0;
            Log ( "server destroyed" );

            // ---- Phase 2: the precondition ----------------------------
            //  If the peer pointer is still set the send below never
            //  reaches the refusal, and a red verdict would be measuring
            //  the wrong thing
            const DWORD_PTR uPeer = pCli -> GetUDState ( );
            std::printf ( "[dmxdead] client GetUDState()=%p (0 means detached)\n",
                          (void *)uPeer );
            std::fflush ( stdout );
            if ( uPeer != 0 )
            {
                std::printf (
                  "\nRESULT: SETUP - the client is still attached to a server\n"
                  "  that is gone, so P2PeerioDmx::SendP2PeerMsg will take its\n"
                  "  normal path and this gate would be measuring nothing.\n"
                  "  That detach is OpenCodeWork.md item 7's territory.\n" );
                nExit = 2;
            }
            else
            {
                // ---- Phase 3: the send must be reported failed --------
                Log ( "--- phase 3: send to the departed peer ---" );
                PostOne ( pCli );

                const bool bClosed =
                    WaitFor ( [&]{ return oClient.Closed ( ); }, 8000 );
                std::printf ( "[dmxdead] clientClosed=%s\n",
                              bClosed ? "yes" : "NO" );
                std::fflush ( stdout );

                if ( bClosed )
                {
                    std::printf (
                      "\nRESULT: PASS - the sender was told.\n"
                      "  A message posted to a DMX connection whose peer has\n"
                      "  gone fails the send and closes the connection,\n"
                      "  instead of being deleted as delivered.\n" );
                    nExit = 0;
                }
                else
                {
                    std::printf (
                      "\nRESULT: FAIL - THE SEND WAS REPORTED AS DELIVERED.\n"
                      "  The peer is gone (GetUDState()==0), a message was\n"
                      "  posted, and the connection is still open eight\n"
                      "  seconds later - so nothing failed and the message is\n"
                      "  gone.  P2PeerioDmx::SendP2PeerMsg sets\n"
                      "  hr = ERROR_OPERATION_ABORTED and then calls\n"
                      "  PostOVERLAPPED, which calls prepareOVERLAPPED, which\n"
                      "  assigns hr = S_OK - so the abort is erased by the\n"
                      "  post it was written for, and the send branch deletes\n"
                      "  the message as sent (P2PeerCon.cpp:691-697).\n"
                      "  Pass the status instead:\n"
                      "    PostOVERLAPPED ( p, ERROR_OPERATION_ABORTED ).\n"
                      "  OpenCodeWork.md item 7, second exit criterion.\n" );
                    nExit = 1;
                }
            }
        }

        // ---- Shutdown -----------------------------------------------
        Log ( "shutdown begin" );
        oClient.CloseHub ( );
        WaitForSingleObject ( hClient, 3000 );
        CloseHandle ( hClient );
        if ( pServer )
        {
            pServer -> CloseHub ( );
            WaitForSingleObject ( hServer, 3000 );
            CloseHandle ( hServer );
            delete pServer;
        }
    }

    CleanupP2Pmsg ( );
    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
