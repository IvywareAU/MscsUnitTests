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
// p2p_dmxcap.cpp - SECURITY GATE TEST: does SetMaxAccepted() bind the DMX
// in-process transport?
//
// BACKGROUND. This is the third asking of one question. p2p_acceptcap asks it
// of P2PeerConWsa and has passed since 2026-08-16; p2p_pipecap asks it of
// P2PeerConPipe and passed on 2026-09-20 only after the fix written for it was
// found inert. OpenCodeWork.md item 2 is the observation behind all three: the
// DECISION helper AcceptAtCapacity() is on the base class (P2PeerCon.h:255),
// and the only call to it in the tree was P2PeerConWsa.cpp:1422. Pipe, serial
// and DMX never asked. P2PeerCon.h:237-238 says why the call cannot simply be
// hoisted into the base - "the refusal itself is transport-specific, because
// only the transport knows how to discard a half-accepted endpoint".
//
// WHY THE DMX REFUSAL IS A DIFFERENT SHAPE FROM THE OTHER TWO, and it is worth
// knowing before reading the phases.
//
//   There is no handle. A DMX link is a pair of P2PeerConDmx objects in one
//   address space pointing at each other through m_pConThat, latched by the
//   CLIENT: P2PeerConDmx::Connect() walks g_oCListP2PeerConDmx for a SERVICE
//   whose m_sServiceName matches, writes both back-pointers itself, and only
//   then posts the service's accept OVERLAPPED (P2PeerConDmx.cpp:788-813). So
//   by the time the service is asked anything, the client is ALREADY attached.
//   Wsa refuses a socket it has not yet adopted; DMX has to detach one.
//
//   Which is why the refusal reuses OnClose()'s exact sequence - clear both
//   back-pointers first, then pConThat->Drop(0) - rather than inventing one.
//   It also has to DropOVERLAPPED the consumed accept, because the normal path
//   does that inside AcceptSpawn() and the tail of P2PeerTarget::On_ConAccept
//   re-arms unconditionally with Accept(), which THROWS on a service that
//   still holds one (P2PeerConDmx.cpp:546-553).
//
//   And there is no raw client. p2p_acceptcap and p2p_pipecap both open the
//   transport by hand - socket(), CreateFile() - on the argument that the
//   adversary does not run this library and will not complete a handshake.
//   That argument has nothing to bite on here: the DMX rendezvous IS library
//   code, in this process, and a "raw" DMX client would be a reimplementation
//   of Connect() rather than a hostile peer. So the clients below are real
//   hubs, and what is being measured is correspondingly narrower - a resource
//   bound against in-process components, not against a remote attacker.
//
// WHAT IT DOES - three phases against one DMX service, cap of ONE.
//
//   Phase 1 (THE POSITIVE CONTROL): client A connects and MUST be served.
//   Without it a transport that refused everything would pass phase 2.
//
//   Phase 2 (THE BOUND): client B connects while A is up, against
//   SetMaxAccepted(1), and MUST NOT be served.
//
//   Phase 3 (THE SERVICE SURVIVED THE REFUSAL, and it is the load-bearing
//   one): the cap is raised to 2 and client C connects. It MUST be served.
//   Without this phase a refusal that killed the listener would pass, because
//   phase 2 cannot tell "B was refused" from "the service stopped accepting
//   at B and would have refused anyone". That is the failure mode the
//   DropOVERLAPPED in the refusal exists to prevent: leave the consumed
//   accept in place and the re-arm at the tail of P2PeerTarget::On_ConAccept
//   throws, after which the service is not listening at all.
//
// WHAT THIS GATE DOES **NOT** ESTABLISH, and the omission is measured rather
// than an oversight. p2p_pipecap closes its first client and requires a later
// one to be served, which is what proves the accepted SLOT is given back.
// That cannot be asserted here, because on this transport it is not true, and
// the cause is a different defect:
//
//   An accepted P2PeerConDmx is never destroyed when its peer goes away, so
//   its accept slot is held for the life of the hub. Measured 2026-09-20:
//   with client A hub CLOSED AND ITS OBJECT DESTROYED, the service
//   GetAcceptedCount() sat at 1 for a further ten seconds and client C was
//   refused. Instrumenting the library showed why, in two steps.
//   P2PeerConDmx::Drop() wakes the peer only when the peer has a QUEUED recv
//   (:454-461) - and on an idle in-process link there is none, because a Dmx
//   "recv" is queued by the SENDER, so the one moment the peer must be woken
//   is the one moment that guard is false. And even once it is woken, nothing
//   destroys it: P2PeerConWsa::OnClose() ends with "Accepted connections MUST
//   always be destroyed and any form of restart blocked" and calls Destroy()
//   (P2PeerConWsa.cpp:2305-2307); P2PeerConDmx::OnClose() has no such line
//   and could not be given one as things stand - P2PeerConDmx, P2PeerConPipe
//   and P2PeerCon232 each DECLARE a non-virtual Destroy() that hides
//   P2PeerConPlc::Destroy() and that nothing in the tree defines, so the call
//   does not link. That was found by making it and reading the linker error.
//
//   It is a resource leak on the in-process transport, and it is a row of its
//   own rather than this one: closing it changes connection teardown for
//   three transports, and doing that from one failing test is the unmeasured
//   change this project keeps being bitten by. OpenCodeWork.md records it.
//   Until it is closed, this gate proves the cap BINDS and does not prove the
//   slot RETURNS.
//
// THE CONTROL IS A SEPARATE CTEST ENTRY, --uncapped, and on this transport it
// is not optional. Nothing here proves a priori that one DMX service can hold
// two accepted connections at once; if it cannot, phase 2 passes against a
// library that does nothing. The control asserts that with SetMaxAccepted(0)
// clients A and B are BOTH served, which is the only thing that makes phase
// 2's refusal attributable to the cap. On the pipe this is exactly the
// distinction that separated two defects that otherwise looked like one.
//
// SERVED means the client's On_ConLoginAck fired. Not "Connect() returned" -
// the latch above makes that true of a client about to be refused - and not
// "On_ConClose did not fire", because a refusal delivered as a silent detach
// would read as success. The login ack is the first event that can only happen
// on a link the service kept.
//
// NO RESOURCE_LOCK IS NEEDED, and that is a property of the transport rather
// than an oversight: every link here is a pointer handoff inside this process.
// There is no port, no pipe name and no COM port for a concurrent test to
// collide with. The service NAME still has to be unique within the process,
// and it is.
//
// Verdict = process EXIT CODE: 0 PASS | 1 FAIL | 2 SETUP | 3 INCONCLUSIVE.

#include "stdafx.h"

#include "P2Pwin32.h"
#include "P2PeerHub.h"
#include "P2PeerConDmx.h"
#include "P2PeerMsg.h"
#include "Msgexception.h"

#include <cstdio>
#include <cstring>
#include <string>

static LPCTSTR          kServiceName = _T("P2PdmxCapProbe");
static const P2PaddrSTR kServerAddr  = L"DmxCap.Server";
static const P2PaddrSTR kClientAddrA = L"DmxCap.ClientA";
static const P2PaddrSTR kClientAddrB = L"DmxCap.ClientB";
static const P2PaddrSTR kClientAddrC = L"DmxCap.ClientC";

static void Log ( const char *lpszMsg )
{
    std::printf ( "[dmxcap] %s\n", lpszMsg );
    std::fflush ( stdout );
}

//  A hub that does nothing but record whether the link it dialled was kept.
//  m_bServed is set from On_ConLoginAck, which is the narrowest event that
//  means "the service accepted me": On_ConConnect fires off the service's
//  OnAccept() notification and so would also fire for a connection the
//  service went on to discard, and Connect() returning proves only that the
//  client managed to latch itself on
class DmxCapHub : public P2PeerHub
{
public:
    DmxCapHub ( P2PaddrSTR strAddr, const char *lpszRole )
      : P2PeerHub ( strAddr ), m_lpszRole ( lpszRole )
      , m_bServed ( false ), m_bClosed ( false ) {}
    virtual ~DmxCapHub ( ) { CloseHub ( ); }

    bool Served ( ) const { return m_bServed; }
    bool Closed ( ) const { return m_bClosed; }

protected:
    virtual conRESULT
      On_ConLoginAck ( P2PeerCon  *pCon
                     , P2PaddrSTR  strThisP2Paddr
                     , P2PaddrSTR  strThatP2Paddr
                     , const void *pvLoginAck
                     , P2Psize_t   iSize ) override
    {
        m_bServed = true;
        std::printf ( "[%s] login ack - SERVED\n", m_lpszRole );
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

private:
    const char   *m_lpszRole;
    volatile bool m_bServed;
    volatile bool m_bClosed;
};

//  Waits for a verdict rather than sleeping a fixed span, so a slow machine
//  costs time instead of a false FAIL.  The in-process rendezvous is fast
//  when it works at all, so the ceiling only has to be generous
static bool WaitServed ( const DmxCapHub &oHub, DWORD dwWaitMs )
{
    for ( DWORD dwWaited = 0; ; dwWaited += 50 )
    {
      if ( oHub.Served ( ) ) return true;
      if ( dwWaited >= dwWaitMs ) return false;
      Sleep ( 50 );
    }
}

int main ( int argc, char *argv[] )
{
    bool bUncapped = false;
    for ( int i = 1; i < argc; ++i )
      if ( std::strcmp ( argv[i], "--uncapped" ) == 0 )
        bUncapped = true;

    const long xCap = bUncapped ? 0 : 1;

    std::printf ( "=== p2p_dmxcap - the accept cap on the DMX transport%s ===\n",
                  bUncapped ? " (CONTROL: uncapped)" : "" );
    std::printf ( "Service : %ls\n", (LPCWSTR)kServiceName );
    std::printf ( "Asserting: %s\n\n",
                  bUncapped
                  ? "with SetMaxAccepted(0), TWO in-process clients are both\n"
                    "           served."
                  : "against SetMaxAccepted(1), the second client is refused,\n"
                    "           the first is untouched, and the service is\n"
                    "           still listening afterwards." );
    std::fflush ( stdout );

    if ( !StartupP2Pmsg ( 16 ) ) { Log ( "SETUP: StartupP2Pmsg() failed" ); return 2; }
    //  (No WSAStartup: the DMX transport opens no socket on either platform.)

    int nExit = 2;
    {
        DmxCapHub oServer ( kServerAddr, "SERVER" );
        //  RequireAuth(false), for p2p_acceptcap's reason: this measures a
        //  RESOURCE bound, spent before a login is attempted, and requiring
        //  auth would drop a client for a second reason
        oServer.RequireAuth ( false );
        HANDLE hServer = oServer.SpawnHub ( );
        if ( !hServer ) { Log ( "SETUP: server SpawnHub() failed" ); return 2; }

        P2PeerConDmx *pSvc = P2PeerConDmx::ServiceFactory ( kClientAddrA, kServiceName );
        if ( !pSvc ) { Log ( "SETUP: ServiceFactory failed" ); return 2; }

        //  The login deadline is OFF, so a client that never logs in can only
        //  have failed to because of the cap.  With both armed this would be
        //  measuring whichever fired first
        pSvc -> SetMaxAccepted   ( xCap );
        pSvc -> SetLoginDeadline ( 0 );
        oServer.PostP2PeerCon ( pSvc );
        std::printf ( "[dmxcap] service posted; SetMaxAccepted(%ld), deadline off\n",
                      xCap );
        std::fflush ( stdout );
        Sleep ( 750 );          // let the pump run Listen() then Accept()

        // ---- Phase 1: the positive control -------------------------------
        Log ( "--- phase 1: client A, which must be served ---" );
        DmxCapHub oClientA ( kClientAddrA, "CLIENT-A" );
        oClientA.RequireAuth ( false );
        HANDLE hClientA = oClientA.SpawnHub ( );
        if ( !hClientA ) { Log ( "SETUP: client A SpawnHub() failed" ); return 2; }
        oClientA.PostP2PeerCon ( P2PeerConDmx::ClientFactory ( kServerAddr, kServiceName ) );

        const bool bAServed = WaitServed ( oClientA, 8000 );
        if ( !bAServed )
        {
            std::printf (
              "\nRESULT: SETUP - the FIRST client was never served.\n"
              "  The service is not accepting at all, so nothing below\n"
              "  measures a bound.  Suspect the refusal being consulted on\n"
              "  every accept rather than at capacity, or the re-arm at the\n"
              "  tail of P2PeerTarget::On_ConAccept throwing because the\n"
              "  refusal path left m_pOVERLAPPEDaccept in place.\n" );
            oClientA.CloseHub ( ); oServer.CloseHub ( );
            WaitForSingleObject ( hClientA, 3000 ); CloseHandle ( hClientA );
            WaitForSingleObject ( hServer,  3000 ); CloseHandle ( hServer  );
            CleanupP2Pmsg ( );
            return 2;
        }

        // ---- Phase 2: the bound ------------------------------------------
        Log ( bUncapped
              ? "--- phase 2: client B, which must ALSO be served ---"
              : "--- phase 2: client B against a cap of one ---" );
        DmxCapHub oClientB ( kClientAddrB, "CLIENT-B" );
        oClientB.RequireAuth ( false );
        HANDLE hClientB = oClientB.SpawnHub ( );
        if ( !hClientB ) { Log ( "SETUP: client B SpawnHub() failed" ); return 2; }
        oClientB.PostP2PeerCon ( P2PeerConDmx::ClientFactory ( kServerAddr, kServiceName ) );

        //  A refused client is EXPECTED to reach Connect() and latch: the
        //  client writes the back-pointers itself before the service is asked
        //  anything.  What it must not reach is a login ack
        const bool bBServed = WaitServed ( oClientB, 5000 );

        std::printf ( "[dmxcap] A=%s B=%s (count=%ld of max %ld)\n",
                      bAServed ? "served" : "NOT SERVED",
                      bBServed ? "SERVED" : "refused",
                      pSvc->GetAcceptedCount ( ), xCap );
        std::fflush ( stdout );

        if ( bUncapped )
        {
            //  The control's whole verdict.  If two in-process clients cannot
            //  both be served when nothing is capping them, then the capped
            //  run's phase 2 is measuring the transport's own limit and its
            //  PASS means nothing
            if ( !bBServed )
            {
                std::printf (
                  "\nRESULT: FAIL - THE CONTROL REFUSED ITS SECOND CLIENT.\n"
                  "  SetMaxAccepted(0) is unbounded, so both clients should\n"
                  "  have been served.  Something other than the cap is\n"
                  "  refusing them and the capped run's verdict cannot be\n"
                  "  trusted until it is understood.  The first suspect is the\n"
                  "  service's own re-arm: P2PeerConDmx::Accept() throws if\n"
                  "  m_pConThat or m_pOVERLAPPEDaccept survived the previous\n"
                  "  accept, and a service that threw there is not listening.\n" );
                nExit = 1;
            }
            else
            {
                std::printf (
                  "\nRESULT: PASS - the control holds.\n"
                  "  Uncapped, two in-process DMX clients are both served, so\n"
                  "  a refusal in the capped run is attributable to the cap.\n" );
                nExit = 0;
            }
        }
        else if ( bBServed )
        {
            std::printf (
              "\nRESULT: FAIL - THE CAP DOES NOT BIND.\n"
              "  SetMaxAccepted(1) is set on the service and a second client\n"
              "  was served anyway (count=%ld).  P2PeerConDmx::OnAccept() must\n"
              "  consult AcceptAtCapacity() BEFORE P2PeerCon::OnAccept()\n"
              "  spawns, and discard the latched client the way OnClose()\n"
              "  does - clear both back-pointers, then pConThat->Drop(0) - and\n"
              "  DropOVERLAPPED the consumed accept so the re-arm at the tail\n"
              "  of P2PeerTarget::On_ConAccept does not throw.\n"
              "  This is OpenCodeWork.md item 2, DMX half.\n",
              pSvc->GetAcceptedCount ( ) );
            nExit = 1;
        }
        else
        {
            // ---- Phase 3: the service survived the refusal ---------------
            //  THE CAP IS RAISED RATHER THAN THE FIRST CLIENT CLOSED, and the
            //  note at the head of this file says at length why: a departing
            //  client does not give its slot back on this transport, for a
            //  reason that is a separate defect.  Raising the bound asks the
            //  question this gate can answer - is the SERVICE still listening
            //  after it refused someone, or did the refusal leave it unable
            //  to re-arm and so refusing everybody?
            Log ( "--- phase 3: the cap is raised, and client C must be "
                  "served ---" );
            pSvc -> SetMaxAccepted ( 2 );
            std::printf ( "[dmxcap] SetMaxAccepted(2); count=%ld\n",
                          pSvc->GetAcceptedCount ( ) );
            std::fflush ( stdout );

            DmxCapHub oClientC ( kClientAddrC, "CLIENT-C" );
            oClientC.RequireAuth ( false );
            HANDLE hClientC = oClientC.SpawnHub ( );
            if ( !hClientC ) { Log ( "SETUP: client C SpawnHub() failed" ); return 2; }
            oClientC.PostP2PeerCon ( P2PeerConDmx::ClientFactory ( kServerAddr, kServiceName ) );

            const bool bCServed = WaitServed ( oClientC, 8000 );
            if ( bCServed )
            {
                std::printf (
                  "\nRESULT: PASS - the cap binds and the service survives it.\n"
                  "  Against SetMaxAccepted(1) the second DMX client was\n"
                  "  refused while the first stayed up, and with the bound\n"
                  "  raised a third was served.  So the refusal is the bound\n"
                  "  and not a listener that died at the first refusal.\n"
                  "  NOT PROVEN HERE: that a departing client gives its slot\n"
                  "  back.  It does not, for a reason that is a separate\n"
                  "  defect - read the note at the head of this file.\n" );
                nExit = 0;
            }
            else
            {
                std::printf (
                  "\nRESULT: FAIL - THE SERVICE DID NOT SURVIVE THE REFUSAL\n"
                  "  (count=%ld of max 2).  A third client was refused with\n"
                  "  the bound raised above the count, so the service stopped\n"
                  "  accepting when it refused the second one rather than\n"
                  "  merely refusing it.  FIRST SUSPECT: the consumed accept.\n"
                  "  The normal path drops m_pOVERLAPPEDaccept inside\n"
                  "  AcceptSpawn(); the refusal has to do it itself, or the\n"
                  "  unconditional re-arm at the tail of\n"
                  "  P2PeerTarget::On_ConAccept reaches P2PeerConDmx::Accept()\n"
                  "  with one still in place and it throws.\n",
                  pSvc->GetAcceptedCount ( ) );
                nExit = 1;
            }

            oClientC.CloseHub ( );
            WaitForSingleObject ( hClientC, 3000 );
            CloseHandle ( hClientC );
        }

        // ---- Shutdown ----------------------------------------------------
        Log ( "shutdown begin" );
        oClientB.CloseHub ( );
        WaitForSingleObject ( hClientB, 3000 );
        CloseHandle ( hClientB );
        oClientA.CloseHub ( );
        WaitForSingleObject ( hClientA, 3000 );
        CloseHandle ( hClientA );
        oServer.CloseHub ( );
        WaitForSingleObject ( hServer, 3000 );
        CloseHandle ( hServer );
    }

    CleanupP2Pmsg ( );
    std::printf ( "Done (exit=%d).\n", nExit );
    std::fflush ( stdout );
    return nExit;
}
